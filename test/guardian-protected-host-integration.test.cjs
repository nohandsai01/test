'use strict';

// Isolated protected-host integration. Loopback-only listener, a real
// file-backed temporary SQLite D1 with the actual Guardian schema, and a
// stubbed GitHub transport. Keys are ephemeral, generated per test run, and
// never leave the process. Any attempt at real network egress fails the run.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const ROOT = '../merge-gate-install/guardian-candidate/';
const paths = {
  collector: require.resolve(ROOT + 'github-rest-collector.cjs'),
  api: require.resolve(ROOT + 'github-app-identity.cjs'),
  authority: require.resolve(ROOT + 'independent-policy-source.cjs'),
};
const DEPENDENT = ['guardian-webhook-runtime.cjs', 'guardian-http-server.cjs',
  'guardian-operator-http.cjs', 'guardian-conclusion-batch.cjs',
  'guardian-conclusion-reconcile.cjs', 'guardian-host-runtime.cjs',
  'guardian-host-bootstrap.cjs'].map((f) => require.resolve(ROOT + f));
const { createGuardianD1Stores } = require(ROOT + 'guardian-d1-stores.cjs');

const REPO = 'nohandsai01/test';
const SHA = 'a'.repeat(40);
const APP = 999;
const INSTALL = 42;
const OWNER = 100;
const REPOSITORY = 88;
const OPERATOR_ORIGIN = 'https://operator.example';
const OWNER_ORIGIN = 'https://owner.example';
const CSRF = 'synthetic-csrf-token-123456789';
const SESSION = 'synthetic-owner-session-123';
const SECRET = crypto.randomBytes(32).toString('hex');

// Ephemeral, in-memory synthetic keys only. No formal App or signer key.
const appKeyPem = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' });
const policyPublic = crypto.generateKeyPairSync('ed25519').publicKey;
const policyPublicPem = policyPublic.export({ type: 'spki', format: 'pem' });
const policyPin = crypto.createHash('sha256')
  .update(policyPublic.export({ type: 'spki', format: 'der' })).digest('hex');

// ---------------------------------------------------------------- stubs
const github = { posts: 0, mints: 0, scopeReads: 0, pullReads: 0,
  failMint: false, failScope: false, failPost: false, failPull: false };
const egress = { attempts: 0 };
const restore = [];
function patch(object, key, value) {
  restore.push({ object, key, previous: object[key] });
  object[key] = value;
}
function resetGithub() {
  Object.assign(github, { posts: 0, mints: 0, scopeReads: 0, pullReads: 0,
    failMint: false, failScope: false, failPost: false, failPull: false });
}
let runtime;

test.before(() => {
  const blocked = () => { egress.attempts++; throw new Error('EGRESS_BLOCKED'); };
  patch(https, 'request', blocked);
  patch(https, 'get', blocked);
  patch(globalThis, 'fetch', async () => blocked());
  const collector = require(paths.collector);
  const api = require(paths.api);
  const authority = require(paths.authority);
  patch(collector, 'readGuardianGithubJson', async (url) => {
    assert.equal(url, '/repos/nohandsai01/test/pulls/12');
    github.pullReads++;
    if (github.failPull) throw new Error('synthetic GitHub GET unavailable');
    return { link: '', body: { number: 12, state: 'open', draft: false,
      base: { ref: 'main', repo: { full_name: REPO, id: REPOSITORY } },
      head: { sha: SHA, repo: { full_name: REPO, id: REPOSITORY } } } };
  });
  patch(collector, 'collectAuthenticatedGithubSnapshot',
    async ({ pullNumber, expectedHeadSha }) => ({ repository: REPO,
      pullRequest: { number: pullNumber, state: 'open',
        base: { ref: 'main', repo: { full_name: REPO } },
        head: { sha: expectedHeadSha, repo: { full_name: REPO } } },
      checkRuns: { total_count: 1, check_runs: [{
        id: 9001, name: 'NO HANDS Merge Gate Required Check',
        app: { id: APP }, head_sha: expectedHeadSha, status: 'completed',
        conclusion: 'failure', completed_at: '2099-01-01T00:00:00Z' }] } }));
  patch(api, 'mintScopedInstallationToken', async ({ privateKeyPem }) => {
    github.mints++;
    assert.equal(privateKeyPem, appKeyPem);
    if (github.failMint) throw new Error('synthetic token endpoint down');
    return { token: 'synthetic-installation-token-not-real' };
  });
  patch(api, 'revalidateCurrentInstallationScope', async () => {
    github.scopeReads++;
    if (github.failScope) throw new Error('synthetic suspended installation');
    return { current: true };
  });
  patch(api, 'postFailureOnlyCheck', async ({ headSha, appId }) => {
    github.posts++;
    assert.equal(headSha, SHA);
    assert.equal(appId, APP);
    if (github.failPost) throw new Error('synthetic uncertain Check POST');
    return { checkRunId: 9001, headSha, conclusion: 'failure' };
  });
  patch(api, 'postConclusiveSuccessCheck', async () => {
    github.posts++;
    throw new Error('success writer must not be reached in this suite');
  });
  patch(authority, 'fetchIndependentlySignedPolicy', async () => null);
  for (const key of DEPENDENT) delete require.cache[key];
  runtime = require(ROOT + 'guardian-host-runtime.cjs');
});

test.after(() => {
  for (const entry of restore.reverse()) entry.object[entry.key] = entry.previous;
  for (const key of DEPENDENT) delete require.cache[key];
  assert.equal(egress.attempts, 0, 'no real network egress is permitted');
});

// ------------------------------------------------------------- fixtures
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'nohands-guardian-host-'));
test.after(() => fs.rmSync(temporary, { recursive: true, force: true }));

function openD1(file, faults = {}) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA busy_timeout = 5000');
  const binding = {
    prepare(sql) {
      const prepared = db.prepare(sql);
      return { bind(...params) { return {
        async run() {
          if (faults.hangWrites) await faults.hangWrites;
          if (faults.failWrites) throw new Error('synthetic D1 write outage');
          const result = prepared.run(...params);
          return { success: true, meta: { changes: Number(result.changes) } };
        },
        async first() {
          if (faults.failReads) throw new Error('synthetic D1 read outage');
          return prepared.get(...params) ?? null;
        },
      }; } };
    },
  };
  return { db, binding };
}
async function freshDatabase(name, { schema = true, bind = true } = {}) {
  const file = path.join(temporary, name + '.sqlite');
  const { db, binding } = openD1(file);
  if (schema) {
    db.exec(fs.readFileSync(path.join(__dirname, ROOT, 'guardian-d1-schema.sql'), 'utf8'));
  }
  if (schema && bind) {
    assert.equal(await createGuardianD1Stores(binding).installationStore.bindVerifiedOnce({
      installationId: INSTALL, appId: APP, ownerAccountId: OWNER,
      repositoryId: REPOSITORY, verifiedAt: new Date().toISOString(),
    }), true);
  }
  db.close();
  return file;
}
function operatorConfig(overrides = {}) {
  return {
    publicOrigin: OPERATOR_ORIGIN,
    authenticateOwnerRequest: async () => ({ sessionId: SESSION, ownerAccountId: OWNER }),
    verifyCsrf: async ({ token }) => token === CSRF,
    rateLimiter: { allow: async () => true },
    issueReadOnlyToken: async () => ({ repositoryId: REPOSITORY, appId: APP,
      value: 'synthetic-read-token-no-github-connection',
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } }),
    ...overrides,
  };
}
function ownerConfig(overrides = {}) {
  return {
    publicOrigin: OWNER_ORIGIN, appSlug: 'nohands-guardian-synthetic',
    clientId: 'Iv1.synthetic0000', clientSecret: crypto.randomBytes(24).toString('hex'),
    authenticateOwnerRequest: async () => ({ sessionId: SESSION, ownerAccountId: OWNER }),
    verifyCsrf: async () => true,
    rateLimiter: { allow: async () => true },
    ...overrides,
  };
}
function hostConfig(d1Binding, overrides = {}) {
  return {
    listen: { host: '127.0.0.1', port: 0 },
    d1Binding,
    webhook: { secret: SECRET, trustedInstallationId: INSTALL },
    githubApp: { appId: APP, privateKeyPem: appKeyPem,
      expectedOwnerAccountId: OWNER, expectedRepositoryId: REPOSITORY },
    policyAuthority: { hostname: 'policy.nohands.example',
      publicKeyPem: policyPublicPem, pinnedSpkiSha256: policyPin },
    checkWrites: { mode: 'FAILURE_ONLY', founderGrant: 'EXPLICIT_FAILURE_ONLY' },
    operatorReadOnly: operatorConfig(),
    ownerOnboarding: ownerConfig(),
    dependencyTimeoutMs: 250,
    drainTimeoutMs: 100,
    ...overrides,
  };
}
async function withHost(file, overrides, run, faults = {}) {
  const { db, binding } = openD1(file, faults);
  const host = runtime.createGuardianProtectedHost(hostConfig(binding, overrides));
  try {
    await host.start();
    return await run(host);
  } finally {
    await host.stop();
    db.close();
  }
}

// --------------------------------------------------------------- client
function request(host, { method = 'GET', url = '/healthz', headers = {}, body = '' } = {}) {
  const { port } = host.address();
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: url,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null') }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
function webhook(host, deliveryId = crypto.randomUUID()) {
  const body = JSON.stringify({ action: 'opened', number: 12,
    repository: { full_name: REPO }, installation: { id: INSTALL },
    pull_request: { number: 12,
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: SHA, repo: { full_name: REPO } } } });
  const signature = 'sha256=' +
    crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return request(host, { method: 'POST', url: '/github/webhook', body,
    headers: { 'content-type': 'application/json',
      'x-github-event': 'pull_request', 'x-github-delivery': deliveryId,
      'x-hub-signature-256': signature } });
}
function operatorRead(host) {
  const body = JSON.stringify({ schemaVersion: 1,
    targets: [{ pullNumber: 12, headSha: SHA }] });
  return request(host, { method: 'POST', url: '/guardian/operator/check-reconcile',
    body, headers: { host: 'operator.example', origin: OPERATOR_ORIGIN,
      'content-type': 'application/json', 'x-guardian-csrf': CSRF } });
}
function assertHold(response) {
  assert.notEqual(response.body.activationAllowed, true);
  assert.notEqual(response.body.releaseAuthorized, true);
  assert.notEqual(response.body.authoritativeRequiredCheck, 'ISSUED');
}
function refused(port) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/healthz',
      agent: false }, () => resolve(false));
    req.on('error', (e) => resolve(e.code === 'ECONNREFUSED'));
    req.end();
  });
}

// ---------------------------------------------------------------- tests
test('host is inert until start, serves on loopback, stops and restarts', async () => {
  resetGithub();
  const file = await freshDatabase('lifecycle');
  const { db, binding } = openD1(file);
  const host = runtime.createGuardianProtectedHost(hostConfig(binding));
  assert.equal(host.state(), 'STOPPED');
  assert.equal(host.address(), null);
  const first = await host.start();
  assert.equal(first.host, '127.0.0.1');
  assert.equal(host.state(), 'RUNNING');
  await assert.rejects(host.start(), { code: 'GUARDIAN_HOST_NOT_STOPPED' });
  const health = await request(host);
  assert.equal(health.status, 200);
  assert.equal(health.body.releaseAuthority, 'NOT_ISSUED');
  const second = await host.restart();
  assert.equal(host.state(), 'RUNNING');
  assert.equal((await request(host)).status, 200);
  await host.stop();
  await host.stop(); // idempotent
  assert.equal(host.state(), 'STOPPED');
  assert.equal(await refused(first.port), true);
  assert.equal(await refused(second.port), true);
  db.close();
  assert.equal(github.posts, 0);
});

test('missing or wrong authorization configuration fails closed before listen', async () => {
  const file = await freshDatabase('config');
  const { db, binding } = openD1(file);
  const ed25519Pem = crypto.generateKeyPairSync('ed25519').privateKey
    .export({ type: 'pkcs8', format: 'pem' });
  const otherPin = crypto.createHash('sha256').update('not-the-key').digest('hex');
  const cases = [
    [{ listen: { host: '0.0.0.0', port: 0 } }, 'GUARDIAN_HOST_BIND_NOT_LOOPBACK'],
    [{ d1Binding: null }, 'GUARDIAN_HOST_D1_BINDING_MISSING'],
    [{ webhook: { secret: 'short', trustedInstallationId: INSTALL } },
      'GUARDIAN_HOST_WEBHOOK_IDENTITY_INVALID'],
    [{ githubApp: { appId: APP, privateKeyPem: ed25519Pem,
      expectedOwnerAccountId: OWNER, expectedRepositoryId: REPOSITORY } },
    'GUARDIAN_HOST_APP_KEY_INVALID'],
    [{ githubApp: { appId: 0, privateKeyPem: appKeyPem,
      expectedOwnerAccountId: OWNER, expectedRepositoryId: REPOSITORY } },
    'GUARDIAN_HOST_APP_IDENTITY_INVALID'],
    [{ checkWrites: { mode: 'FULL' } }, 'GUARDIAN_HOST_WRITE_GRANT_INVALID'],
    [{ checkWrites: { mode: 'FAILURE_ONLY', founderGrant: 'EXPLICIT_FULL_CHECK_WRITES' } },
      'GUARDIAN_HOST_WRITE_GRANT_INVALID'],
    [{ checkWrites: { mode: 'OFF', founderGrant: 'EXPLICIT_FAILURE_ONLY' } },
      'GUARDIAN_HOST_WRITE_GRANT_INVALID'],
    [{ checkWrites: { mode: 'BOTH' } }, 'GUARDIAN_HOST_WRITE_MODE_INVALID'],
    [{ enableFullCheckWrites: true }, 'GUARDIAN_HOST_CONFIG_SHAPE_INVALID'],
    [{ operatorReadOnly: operatorConfig({ issueReadOnlyToken: undefined }) },
      'GUARDIAN_HOST_OPERATOR_AUTHORITY_MISSING'],
    [{ operatorReadOnly: operatorConfig({ conclusionStore: {} }) },
      'GUARDIAN_HOST_OPERATOR_CONFIG_INVALID'],
    [{ operatorReadOnly: operatorConfig({ authenticateOwnerRequest: 'yes' }) },
      'GUARDIAN_HOST_OPERATOR_AUTHORITY_MISSING'],
    [{ operatorReadOnly: operatorConfig({ publicOrigin: 'http://operator.example' }) },
      'GUARDIAN_HOST_OPERATOR_ORIGIN_INVALID'],
    [{ ownerOnboarding: ownerConfig({ verifyCsrf: null }) },
      'GUARDIAN_HOST_OWNER_AUTHORITY_MISSING'],
    [{ ownerOnboarding: ownerConfig({ clientSecret: 'short' }) },
      'GUARDIAN_HOST_OWNER_APP_IDENTITY_INVALID'],
    [{ policyAuthority: { hostname: 'policy.nohands.example',
      publicKeyPem: policyPublicPem, pinnedSpkiSha256: otherPin } },
    'GUARDIAN_HOST_POLICY_FINGERPRINT_MISMATCH'],
    [{ policyAuthority: { hostname: 'evil.github.com',
      publicKeyPem: policyPublicPem, pinnedSpkiSha256: policyPin } },
    'GUARDIAN_HOST_POLICY_AUTHORITY_INVALID'],
    [{ dependencyTimeoutMs: 0 }, 'GUARDIAN_HOST_TIMEOUT_INVALID'],
  ];
  for (const [override, code] of cases) {
    assert.throws(() => runtime.createGuardianProtectedHost(hostConfig(binding, override)),
      (error) => error.code === code && !String(error.message).includes(SECRET),
      code);
  }
  db.close();
});

test('missing D1 schema or unreadable D1 refuses start with no listener', async () => {
  const empty = await freshDatabase('no-schema', { schema: false });
  const { db, binding } = openD1(empty);
  const host = runtime.createGuardianProtectedHost(hostConfig(binding));
  await assert.rejects(host.start(), { code: 'GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE' });
  assert.equal(host.state(), 'STOPPED');
  assert.equal(host.address(), null);
  db.close();
  const file = await freshDatabase('unreadable');
  const broken = openD1(file, { failReads: true });
  const second = runtime.createGuardianProtectedHost(hostConfig(broken.binding));
  await assert.rejects(second.start(), { code: 'GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE' });
  broken.db.close();
});

test('Check Run publishes once and restarts never republish', async () => {
  resetGithub();
  const file = await freshDatabase('restart');
  const delivery = crypto.randomUUID();
  await withHost(file, {}, async (host) => {
    const first = await webhook(host, delivery);
    assert.equal(first.status, 202);
    assert.equal(first.body.status, 'CHECK_RUN_RECORDED_RELEASE_HOLD');
    assert.equal(first.body.reason, 'FAILURE_ONLY_CHECK_RECORDED');
    assertHold(first);
    assert.equal(github.posts, 1);
    // Same process restart: new server, same durable D1 file.
    await host.restart();
    const replay = await webhook(host, delivery);
    assert.equal(replay.body.reason, 'DELIVERY_DUPLICATE_OR_NOT_RESERVED');
    assertHold(replay);
  });
  // Cold restart: new host object and a new SQLite connection.
  await withHost(file, {}, async (host) => {
    const replay = await webhook(host, delivery);
    assert.equal(replay.body.reason, 'DELIVERY_DUPLICATE_OR_NOT_RESERVED');
    const other = await webhook(host);
    assert.equal(other.status, 202);
    assert.equal(other.body.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
    assertHold(other);
    // Operator observation is read-only and grants nothing.
    const observed = await operatorRead(host);
    assert.equal(observed.status, 200);
    assert.equal(observed.body.observations[0].reservationObserved, true);
    assert.equal(observed.body.automaticRetryAllowed, false);
    assertHold(observed);
  });
  assert.equal(github.posts, 1);
});

test('D1 outages and hangs keep HOLD and never reach Check egress', async () => {
  resetGithub();
  const file = await freshDatabase('d1-faults');
  await withHost(file, {}, async (host) => {
    const failed = await webhook(host);
    assert.equal(failed.status, 503);
    assert.equal(failed.body.status, 'SOURCE_ONLY_HOLD');
    assertHold(failed);
  }, { failWrites: true });
  let release;
  const hang = new Promise((resolve) => { release = resolve; });
  await withHost(file, {}, async (host) => {
    const started = Date.now();
    const timedOut = await webhook(host);
    assert.equal(timedOut.status, 503);
    assert.equal(timedOut.body.reason, 'DELIVERY_REPLAY_STORE_FAILED');
    assert.ok(Date.now() - started < 3000);
    assertHold(timedOut);
    // Healthy routes stay isolated from the stalled dependency.
    assert.equal((await request(host)).status, 200);
  }, { hangWrites: hang });
  release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(github.posts, 0);
});

test('GitHub failures keep HOLD and an uncertain POST is never retried', async () => {
  resetGithub();
  const file = await freshDatabase('github-faults');
  await withHost(file, {}, async (host) => {
    github.failMint = true;
    const mint = await webhook(host);
    assert.equal(mint.body.reason, 'GITHUB_APP_INSTALLATION_TOKEN_UNAVAILABLE');
    github.failMint = false;
    github.failScope = true;
    const scope = await webhook(host);
    assert.equal(scope.body.reason, 'FRESH_INSTALLATION_SCOPE_UNVERIFIED');
    github.failScope = false;
    github.failPull = true;
    const pull = await webhook(host);
    assert.equal(pull.body.reason, 'FRESH_PR_TARGET_UNVERIFIED');
    github.failPull = false;
    for (const r of [mint, scope, pull]) { assert.equal(r.status, 503); assertHold(r); }
    assert.equal(github.posts, 0);
    github.failPost = true;
    const uncertain = await webhook(host);
    assert.equal(uncertain.status, 503);
    assert.equal(uncertain.body.reason, 'FAILURE_ONLY_CHECK_NOT_CONFIRMED');
    assertHold(uncertain);
    github.failPost = false;
    await host.restart();
    const after = await webhook(host);
    assert.equal(after.body.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
    assertHold(after);
  });
  assert.equal(github.posts, 1, 'exactly one uncertain attempt, never retried');
});

test('owner and operator authority faults are isolated and fail closed', async () => {
  resetGithub();
  const file = await freshDatabase('authority-faults');
  const overrides = {
    operatorReadOnly: operatorConfig({
      authenticateOwnerRequest: async () => { throw new Error('auth backend down'); },
    }),
    ownerOnboarding: ownerConfig({
      authenticateOwnerRequest: () => new Promise(() => {}),
    }),
  };
  await withHost(file, overrides, async (host) => {
    const operator = await operatorRead(host);
    assert.equal(operator.status, 401);
    assert.equal(operator.body.reason, 'GUARDIAN_OPERATOR_AUTH_UNVERIFIED');
    assertHold(operator);
    const owner = await request(host, { url: '/guardian/install/setup?installation_id=1',
      headers: { host: 'owner.example' } });
    assert.equal(owner.status, 401);
    assert.equal(owner.body.status, 'INSTALLATION_HOLD');
    assert.equal(owner.body.activated, false);
    assert.equal((await request(host)).status, 200);
  });
  assert.equal(github.posts, 0);
});

test('stop is bounded under a stalled request and fences late D1 results', async () => {
  resetGithub();
  const file = await freshDatabase('stop-fence');
  const { db, binding } = openD1(file, { hangWrites: new Promise(() => {}) });
  let releaseLate;
  const late = new Promise((resolve) => { releaseLate = resolve; });
  const slowBinding = { prepare(sql) {
    const statement = binding.prepare(sql);
    return { bind(...p) {
      const bound = statement.bind(...p);
      return { first: () => bound.first(),
        run: async () => { await late; return { success: true, meta: { changes: 1 } }; } };
    } };
  } };
  const host = runtime.createGuardianProtectedHost(hostConfig(slowBinding,
    { dependencyTimeoutMs: 30_000, drainTimeoutMs: 50 }));
  const { port } = await host.start();
  const pending = webhook(host).then(() => 'answered', () => 'disconnected');
  await new Promise((resolve) => setTimeout(resolve, 100));
  const started = Date.now();
  await host.stop();
  assert.ok(Date.now() - started < 2000, 'stop must not wait for the stalled dependency');
  assert.equal(await pending, 'disconnected');
  assert.equal(await refused(port), true);
  releaseLate();
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(github.posts, 0, 'late dependency success must not reach egress');
  assert.equal(github.mints, 0);
  db.close();
});
