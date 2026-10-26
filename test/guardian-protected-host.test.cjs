'use strict';

// Protected-host lifecycle integration. Loopback-only listener, a real
// temporary SQLite database with the actual Guardian schema as the isolated
// D1 binding, ephemeral synthetic keys and stubbed GitHub transports.
// No network egress, no real GitHub App, no real D1 and no real Check write.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const ROOT = '../merge-gate-install/guardian-candidate/';
const paths = {
  host: require.resolve(ROOT + 'guardian-protected-host.cjs'),
  server: require.resolve(ROOT + 'guardian-http-server.cjs'),
  runtime: require.resolve(ROOT + 'guardian-webhook-runtime.cjs'),
  operator: require.resolve(ROOT + 'guardian-operator-http.cjs'),
  api: require.resolve(ROOT + 'github-app-identity.cjs'),
  collector: require.resolve(ROOT + 'github-rest-collector.cjs'),
  authority: require.resolve(ROOT + 'independent-policy-source.cjs'),
  evaluator: require.resolve(ROOT + 'read-and-evaluate.cjs'),
  signed: require.resolve(ROOT + 'signed-policy.cjs'),
};
const SCHEMA = fs.readFileSync(path.join(__dirname, ROOT, 'guardian-d1-schema.sql'), 'utf8');

const SHA = 'a'.repeat(40);
const APP = 999;
const INSTALL = 42;
const OWNER = 100;
const REPOSITORY = 88;
const REPO = 'nohandsai01/test';
const SECRET = 'synthetic-host-webhook-secret-' + 'z'.repeat(35);
const APP_KEY = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ format: 'pem', type: 'pkcs8' });
const POLICY_PUBLIC = crypto.generateKeyPairSync('ed25519').publicKey;
const POLICY_PEM = POLICY_PUBLIC.export({ format: 'pem', type: 'spki' });
const POLICY_PIN = crypto.createHash('sha256')
  .update(POLICY_PUBLIC.export({ format: 'der', type: 'spki' })).digest('hex');

function openDb(file, { schema = true, binding = true } = {}) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA busy_timeout = 5000');
  if (schema) db.exec(SCHEMA);
  if (schema && binding) {
    db.prepare('INSERT OR IGNORE INTO guardian_installation_bindings ' +
      '(installation_id, app_id, owner_account_id, repository_id, verified_at) ' +
      'VALUES (?, ?, ?, ?, ?)').run(INSTALL, APP, OWNER, REPOSITORY,
      '2026-10-26T00:00:00.000Z');
  }
  return db;
}
function d1(db, faults = { mode: null, prepares: 0 }) {
  return {
    prepare(sql) {
      faults.prepares++;
      if (faults.mode === 'throw') throw new Error('synthetic D1 outage');
      const statement = db.prepare(sql);
      return { bind(...args) { return {
        async run() {
          const result = statement.run(...args);
          return { success: true, meta: { changes: Number(result.changes) } };
        },
        async first() {
          if (faults.mode === 'badRow') return [];
          return statement.get(...args) ?? null;
        },
      }; } };
    },
  };
}
function count(db, table) {
  return db.prepare('SELECT COUNT(*) AS n FROM ' + table).get().n;
}
function tempFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nohands-guardian-host-'));
  return { file: path.join(dir, 'guardian.sqlite'), dir };
}

function baseConfig(binding, overrides = {}) {
  return {
    listenAddress: '127.0.0.1', port: 0,
    mode: 'FAILURE_ONLY', modeGrant: 'EXPLICIT_FAILURE_ONLY',
    guardianAppId: APP, trustedInstallationId: INSTALL,
    expectedOwnerAccountId: OWNER, expectedRepositoryId: REPOSITORY,
    webhookSecret: SECRET, githubAppPrivateKeyPem: APP_KEY,
    policyAuthority: { hostname: 'policy.example.com', publicKeyPem: POLICY_PEM,
      pinnedSpkiSha256: POLICY_PIN },
    d1Binding: binding,
    ...overrides,
  };
}

function currentPr(headSha = SHA) {
  return { number: 12, state: 'open', draft: false,
    base: { ref: 'main', repo: { full_name: REPO, id: REPOSITORY } },
    head: { sha: headSha, repo: { full_name: REPO, id: REPOSITORY } } };
}

// Stubs every GitHub/policy transport the runtime and host use, then loads
// fresh copies of host -> server -> runtime so the stubs are bound.
async function withStubs(options, run) {
  const modules = Object.fromEntries(['api', 'collector', 'authority',
    'evaluator', 'signed', 'operator'].map((k) => [k, require(paths[k])]));
  const patches = [];
  const patch = (object, key, value) => {
    patches.push({ object, key, previous: object[key] });
    object[key] = value;
  };
  const calls = { mints: 0, scopes: 0, failureWrites: 0, successWrites: 0,
    pulls: 0, egress: 0, operatorHosts: [] };
  patch(https, 'request', () => { calls.egress++; throw new Error('egress blocked'); });
  patch(https, 'get', () => { calls.egress++; throw new Error('egress blocked'); });
  patch(modules.api, 'mintScopedInstallationToken', async (input) => {
    calls.mints++;
    if (options.mint) return options.mint(input, calls);
    return { token: 'synthetic-installation-token-long-enough' };
  });
  patch(modules.api, 'revalidateCurrentInstallationScope', async () => {
    calls.scopes++;
    if (options.scope) return options.scope(calls);
    return { current: true };
  });
  patch(modules.api, 'postFailureOnlyCheck', async ({ headSha, appId }) => {
    calls.failureWrites++;
    assert.equal(headSha, SHA);
    assert.equal(appId, APP);
    if (options.post) return options.post(calls);
    return { checkRunId: 9001, headSha, conclusion: 'failure' };
  });
  patch(modules.api, 'postConclusiveSuccessCheck', async ({ headSha }) => {
    calls.successWrites++;
    if (options.post) return options.post(calls);
    return { checkRunId: 9002, headSha, conclusion: 'success' };
  });
  patch(modules.collector, 'readGuardianGithubJson', async () => {
    calls.pulls++;
    return { body: currentPr(), link: '' };
  });
  patch(modules.authority, 'fetchIndependentlySignedPolicy', async () =>
    ({ envelope: 'synthetic-envelope', publicKeyPem: 'synthetic-key' }));
  patch(modules.evaluator, 'readAndEvaluateGuardianCandidate', async () =>
    options.eligible ? { reason: 'EVIDENCE_CONCLUSIVE_CANDIDATE',
      eligibleForSuccess: true, signedPolicySha256: 'synthetic-digest' } :
      { reason: 'GUARDIAN_REVIEW_APPROVALS_INSUFFICIENT', eligibleForSuccess: false });
  patch(modules.signed, 'verifySignedPolicy', () => ({ signatureChecked: true,
    headSha: SHA, payloadSha256: 'synthetic-digest',
    releasePolicy: { guardianAppId: APP } }));
  const realOperator = modules.operator.createGuardianOperatorHttpHandler;
  patch(modules.operator, 'createGuardianOperatorHttpHandler', ({ host }) => {
    calls.operatorHosts.push(host);
    return realOperator({ host });
  });
  for (const key of ['host', 'server', 'runtime']) delete require.cache[paths[key]];
  const hostModule = require(paths.host);
  const created = [];
  const createGuardianProtectedHost = (config) => {
    const host = hostModule.createGuardianProtectedHost(config);
    created.push(host);
    return host;
  };
  try {
    return await run({ ...hostModule, createGuardianProtectedHost, calls });
  } finally {
    // A failed assertion must never leave a loopback listener running.
    for (const host of created) {
      if (host.status().state === 'RUNNING') await host.stop().catch(() => {});
    }
    for (const entry of patches.reverse()) entry.object[entry.key] = entry.previous;
    for (const key of ['host', 'server', 'runtime']) delete require.cache[paths[key]];
  }
}

function request(port, { method = 'GET', target = '/healthz', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const content = body === undefined ? null : Buffer.from(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: target, method,
      agent: false, headers: { ...(content ? { 'Content-Length': content.length } : {}),
        ...headers } }, (res) => {
      const bytes = [];
      res.on('data', (part) => bytes.push(part));
      res.on('end', () => resolve({ status: res.statusCode,
        json: JSON.parse(Buffer.concat(bytes).toString('utf8') || 'null') }));
    });
    req.on('error', reject);
    if (content) req.write(content);
    req.end();
  });
}
function webhook(port, deliveryId = crypto.randomUUID(), secret = SECRET) {
  const body = JSON.stringify({ action: 'synchronize', number: 12,
    repository: { full_name: REPO }, installation: { id: INSTALL },
    pull_request: { number: 12,
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: SHA, repo: { full_name: REPO } } } });
  const signature = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return request(port, { method: 'POST', target: '/github/webhook', body, headers: {
    'Content-Type': 'application/json', 'X-GitHub-Event': 'pull_request',
    'X-GitHub-Delivery': deliveryId, 'X-Hub-Signature-256': 'sha256=' + signature } });
}
const portOf = (host) => host.status().address.port;

test('configuration errors fail closed at construction with field-only codes', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const binding = d1(db);
    const weakKey = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })
      .privateKey.export({ format: 'pem', type: 'pkcs8' });
    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
      .privateKey.export({ format: 'pem', type: 'pkcs8' });
    const otherPolicy = crypto.generateKeyPairSync('ed25519').publicKey
      .export({ format: 'pem', type: 'spki' });
    const rsaPublic = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ format: 'pem', type: 'spki' });
    const cases = [
      [{ webhookSecret: undefined }, 'webhookSecret'],
      [{ webhookSecret: 'short' }, 'webhookSecret'],
      [{ listenAddress: '0.0.0.0' }, 'listenAddress'],
      [{ listenAddress: '192.168.1.5' }, 'listenAddress'],
      [{ port: 70000 }, 'port'],
      [{ mode: 'FULL', modeGrant: undefined }, 'modeGrant'],
      [{ mode: 'FULL', modeGrant: 'EXPLICIT_FAILURE_ONLY' }, 'modeGrant'],
      [{ mode: 'FAILURE_ONLY', modeGrant: 'EXPLICIT_FULL_CHECK_WRITES' }, 'modeGrant'],
      [{ mode: 'OFF', modeGrant: 'EXPLICIT_FAILURE_ONLY' }, 'modeGrant'],
      [{ mode: 'BOTH' }, 'mode'],
      [{ guardianAppId: 0 }, 'guardianAppId'],
      [{ trustedInstallationId: '42' }, 'trustedInstallationId'],
      [{ expectedRepositoryId: -1 }, 'expectedRepositoryId'],
      [{ githubAppPrivateKeyPem: weakKey }, 'githubAppPrivateKeyPem'],
      [{ githubAppPrivateKeyPem: ecKey }, 'githubAppPrivateKeyPem'],
      [{ githubAppPrivateKeyPem: 'x'.repeat(200) }, 'githubAppPrivateKeyPem'],
      [{ policyAuthority: { hostname: 'policy.example.com', publicKeyPem: otherPolicy,
        pinnedSpkiSha256: POLICY_PIN } }, 'policyAuthority'],
      [{ policyAuthority: { hostname: 'policy.example.com', publicKeyPem: rsaPublic,
        pinnedSpkiSha256: POLICY_PIN } }, 'policyAuthority'],
      [{ policyAuthority: { hostname: 'policy.example.com', publicKeyPem: POLICY_PEM,
        pinnedSpkiSha256: POLICY_PIN, extra: 1 } }, 'policyAuthority'],
      [{ d1Binding: {} }, 'd1Binding'],
      [{ deliveryStore: { reserveOnce: async () => true } }, 'deliveryStore'],
      [{ conclusionStore: { reserveOnce: async () => true } }, 'conclusionStore'],
      [{ dependencyFaultThreshold: 0 }, 'dependencyFaultThreshold'],
      [{ startupTimeoutMs: 10 }, 'startupTimeoutMs'],
      [{ operatorReadOnly: { publicOrigin: 'https://operator.example',
        authenticateOwnerRequest: async () => null, verifyCsrf: async () => true,
        rateLimiter: { allow: async () => true } } }, 'operatorReadOnly'],
      [{ operatorReadOnly: { publicOrigin: 'https://operator.example',
        conclusionStore: {} } }, 'operatorReadOnly'],
      [{ ownerOnboarding: { publicOrigin: 'https://owner.example' } }, 'ownerOnboarding'],
    ];
    for (const [overrides, field] of cases) {
      const config = baseConfig(binding, overrides);
      for (const key of Object.keys(overrides)) {
        if (overrides[key] === undefined) delete config[key];
      }
      assert.throws(() => createGuardianProtectedHost(config), (error) =>
        error.code === 'GUARDIAN_HOST_CONFIG_INVALID' && error.field === field &&
        !error.message.includes(SECRET) && !error.message.includes('PRIVATE KEY'),
      field);
    }
    assert.deepEqual([calls.mints, calls.scopes, calls.egress, calls.failureWrites],
      [0, 0, 0, 0]);
    db.close();
  });
});

test('startup probes fail closed: no listener when D1, binding or GitHub identity is unverified', async () => {
  const scenarios = [
    { name: 'schema missing', db: () => openDb(':memory:', { schema: false }),
      code: 'GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE' },
    { name: 'binding missing', db: () => openDb(':memory:', { binding: false }),
      code: 'GUARDIAN_HOST_INSTALLATION_BINDING_UNVERIFIED' },
    { name: 'binding for another app', db: () => {
      const db = openDb(':memory:', { binding: false });
      db.prepare('INSERT INTO guardian_installation_bindings VALUES (?, ?, ?, ?, ?)')
        .run(INSTALL, APP + 1, OWNER, REPOSITORY, '2026-10-26T00:00:00.000Z');
      return db;
    }, code: 'GUARDIAN_HOST_INSTALLATION_BINDING_UNVERIFIED' },
    { name: 'token mint rejected', stubs: { mint: () => { throw new Error('401'); } },
      code: 'GUARDIAN_HOST_GITHUB_IDENTITY_UNVERIFIED' },
    { name: 'scope revalidation rejected',
      stubs: { scope: () => { throw new Error('suspended'); } },
      code: 'GUARDIAN_HOST_GITHUB_IDENTITY_UNVERIFIED' },
    { name: 'GitHub hangs', stubs: { mint: () => new Promise(() => {}) },
      overrides: { startupTimeoutMs: 100 }, code: 'GUARDIAN_HOST_STARTUP_TIMEOUT' },
  ];
  for (const scenario of scenarios) {
    await withStubs(scenario.stubs || {}, async ({ createGuardianProtectedHost, calls }) => {
      const db = scenario.db ? scenario.db() : openDb(':memory:');
      const host = createGuardianProtectedHost(baseConfig(d1(db), scenario.overrides));
      await assert.rejects(host.start(), (error) => error.code === scenario.code,
        scenario.name);
      const status = host.status();
      assert.equal(status.state, 'FAILED', scenario.name);
      assert.equal(status.address, null, scenario.name);
      assert.equal(status.activationAllowed, false);
      assert.equal(calls.failureWrites + calls.successWrites, 0, scenario.name);
      if (scenario.name !== 'schema missing') {
        assert.equal(count(db, 'guardian_conclusion_reservations'), 0);
      }
      db.close();
    });
  }
});

test('OFF mode starts without GitHub identity calls and never reserves or publishes', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db),
      { mode: 'OFF', modeGrant: undefined }));
    await host.start();
    const health = await request(portOf(host));
    assert.equal(health.status, 200);
    const response = await webhook(portOf(host));
    assert.equal(response.status, 503);
    assert.equal(response.json.reason, 'FEATURE_OFF');
    assert.equal(response.json.activationAllowed, false);
    assert.deepEqual([calls.mints, calls.scopes, calls.failureWrites, calls.egress],
      [0, 0, 0, 0]);
    assert.equal(count(db, 'guardian_delivery_receipts'), 0);
    await host.stop();
    db.close();
  });
});

test('failure-only host starts, records exactly one Check, stops and refuses traffic', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db)));
    const started = await host.start();
    assert.equal(started.state, 'RUNNING');
    assert.equal(started.address.address, '127.0.0.1');
    assert.equal(calls.mints, 1);
    assert.equal(calls.scopes, 1);
    const forged = await webhook(portOf(host), crypto.randomUUID(),
      'forged-secret-' + 'q'.repeat(40));
    assert.equal(forged.status, 401);
    const response = await webhook(portOf(host));
    assert.equal(response.status, 202);
    assert.equal(response.json.status, 'CHECK_RUN_RECORDED_RELEASE_HOLD');
    assert.equal(response.json.activationAllowed, false);
    assert.equal(calls.failureWrites, 1);
    assert.equal(count(db, 'guardian_delivery_receipts'), 1);
    assert.equal(count(db, 'guardian_conclusion_reservations'), 1);
    const port = portOf(host);
    const stopped = await host.stop();
    assert.equal(stopped.state, 'STOPPED');
    assert.equal(stopped.address, null);
    assert.equal(stopped.abandonedInFlight, 0);
    await assert.rejects(request(port), /ECONNREFUSED/);
    assert.equal(calls.egress, 0);
    db.close();
  });
});

test('restart and a new process on the same D1 never publish a second Check for the head', async () => {
  const { file, dir } = tempFile();
  try {
    await withStubs({ eligible: true }, async ({ createGuardianProtectedHost, calls }) => {
      const db = openDb(file);
      const full = createGuardianProtectedHost(baseConfig(d1(db),
        { mode: 'FULL', modeGrant: 'EXPLICIT_FULL_CHECK_WRITES' }));
      await full.start();
      const delivery = crypto.randomUUID();
      const first = await webhook(portOf(full), delivery);
      assert.equal(first.json.reason, 'SUCCESS_CHECK_RECORDED_RELEASE_HOLD');
      assert.equal(calls.successWrites, 1);
      await full.restart();
      assert.equal(full.status().state, 'RUNNING');
      const replay = await webhook(portOf(full), delivery);
      assert.equal(replay.json.reason, 'DELIVERY_DUPLICATE_OR_NOT_RESERVED');
      const again = await webhook(portOf(full));
      assert.equal(again.json.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
      await full.stop();
      db.close();

      // Fresh process: new connection, different mode, same durable D1 file.
      const db2 = openDb(file);
      const failureHost = createGuardianProtectedHost(baseConfig(d1(db2)));
      await failureHost.start();
      const crossMode = await webhook(portOf(failureHost));
      assert.equal(crossMode.json.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
      const oldReplay = await webhook(portOf(failureHost), delivery);
      assert.equal(oldReplay.json.reason, 'DELIVERY_DUPLICATE_OR_NOT_RESERVED');
      assert.deepEqual([calls.successWrites, calls.failureWrites], [1, 0]);
      assert.equal(count(db2, 'guardian_conclusion_reservations'), 1);
      await failureHost.stop();
      db2.close();
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('two host instances on one D1 with distinct deliveries publish once for the same head', async () => {
  const { file, dir } = tempFile();
  try {
    await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
      const dbA = openDb(file), dbB = openDb(file);
      const a = createGuardianProtectedHost(baseConfig(d1(dbA)));
      const b = createGuardianProtectedHost(baseConfig(d1(dbB)));
      await Promise.all([a.start(), b.start()]);
      const results = await Promise.all([
        webhook(portOf(a)), webhook(portOf(b)), webhook(portOf(a)), webhook(portOf(b)),
      ]);
      const reasons = results.map((r) => r.json.reason);
      assert.equal(reasons.filter((r) => r === 'FAILURE_ONLY_CHECK_RECORDED').length, 1);
      assert.equal(reasons.filter((r) =>
        r === 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED').length, 3);
      assert.equal(calls.failureWrites, 1);
      assert.equal(count(dbA, 'guardian_delivery_receipts'), 4);
      await Promise.all([a.stop(), b.stop()]);
      dbA.close(); dbB.close();
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('uncertain Check POST is never retried after restart', async () => {
  const { file, dir } = tempFile();
  try {
    await withStubs({ post: () => { throw new Error('socket reset after send'); } },
      async ({ createGuardianProtectedHost, calls }) => {
        const db = openDb(file);
        const host = createGuardianProtectedHost(baseConfig(d1(db)));
        await host.start();
        const uncertain = await webhook(portOf(host));
        assert.equal(uncertain.status, 503);
        assert.equal(uncertain.json.reason, 'FAILURE_ONLY_CHECK_NOT_CONFIRMED');
        await host.restart();
        const later = await webhook(portOf(host));
        assert.equal(later.json.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
        assert.equal(calls.failureWrites, 1);
        await host.stop();
        db.close();
      });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('repeated D1 faults latch HOLD; healing D1 alone does not release it; restart re-probes', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const faults = { mode: null, prepares: 0 };
    const host = createGuardianProtectedHost(baseConfig(d1(db, faults),
      { dependencyFaultThreshold: 2 }));
    await host.start();
    faults.mode = 'throw';
    for (let i = 0; i < 2; i++) {
      const response = await webhook(portOf(host));
      assert.equal(response.status, 503);
      assert.equal(response.json.reason, 'INSTALLATION_BINDING_READ_FAILED');
    }
    assert.equal(host.status().dependencyHold, true);
    assert.equal(host.status().holdReason, 'GUARDIAN_HOST_D1_FAULT_HOLD');
    faults.mode = null;
    const prepares = faults.prepares;
    const held = await webhook(portOf(host));
    assert.equal(held.status, 503);
    assert.equal(held.json.reason, 'GUARDIAN_HOST_D1_FAULT_HOLD');
    assert.equal((await request(portOf(host))).status, 503);
    assert.equal(faults.prepares, prepares, 'held host must not touch D1');
    assert.equal(calls.failureWrites, 0);

    faults.mode = 'throw';
    await assert.rejects(host.restart(), /GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE/);
    assert.equal(host.status().state, 'FAILED');
    assert.equal(host.status().dependencyHold, true);
    faults.mode = null;
    await host.start();
    assert.equal(host.status().dependencyHold, false);
    const recovered = await webhook(portOf(host));
    assert.equal(recovered.json.reason, 'FAILURE_ONLY_CHECK_RECORDED');
    assert.equal(calls.failureWrites, 1);
    await host.stop();
    db.close();
  });
});

test('a single D1 integrity fault latches HOLD immediately', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const faults = { mode: null, prepares: 0 };
    const host = createGuardianProtectedHost(baseConfig(d1(db, faults)));
    await host.start();
    faults.mode = 'badRow';
    const response = await webhook(portOf(host));
    assert.equal(response.status, 503);
    assert.equal(host.status().holdReason, 'GUARDIAN_HOST_D1_INTEGRITY_HOLD');
    faults.mode = null;
    assert.equal((await webhook(portOf(host))).json.reason, 'GUARDIAN_HOST_D1_INTEGRITY_HOLD');
    assert.equal(calls.failureWrites, 0);
    await host.stop();
    db.close();
  });
});

test('GitHub scope fault during delivery holds without a Check or conclusion row', async () => {
  await withStubs({ scope: (calls) => {
    if (calls.scopes > 1) throw new Error('installation suspended');
    return { current: true };
  } }, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db)));
    await host.start();
    const response = await webhook(portOf(host));
    assert.equal(response.status, 503);
    assert.equal(response.json.reason, 'FRESH_INSTALLATION_SCOPE_UNVERIFIED');
    assert.equal(calls.failureWrites, 0);
    assert.equal(count(db, 'guardian_conclusion_reservations'), 0);
    await host.stop();
    db.close();
  });
});

test('stop drains an in-flight delivery; drain timeout abandons it without enabling a retry', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await withStubs({ post: async () => { await gate;
    return { checkRunId: 9001, headSha: SHA, conclusion: 'failure' }; } },
  async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db), { drainTimeoutMs: 2000 }));
    await host.start();
    const port = portOf(host);
    const pending = webhook(port);
    while (calls.failureWrites === 0) await new Promise((r) => setTimeout(r, 5));
    const stopping = host.stop();
    assert.equal(host.status().state, 'STOPPING');
    await assert.rejects(request(port), /ECONNREFUSED|ECONNRESET|socket hang up/);
    release();
    const delivered = await pending;
    assert.equal(delivered.json.reason, 'FAILURE_ONLY_CHECK_RECORDED');
    const stopped = await stopping;
    assert.equal(stopped.abandonedInFlight, 0);
    db.close();
  });

  await withStubs({ post: () => new Promise(() => {}) },
    async ({ createGuardianProtectedHost, calls }) => {
      const db = openDb(':memory:');
      const host = createGuardianProtectedHost(baseConfig(d1(db), { drainTimeoutMs: 50 }));
      await host.start();
      const pending = webhook(portOf(host)).catch((error) => error);
      while (calls.failureWrites === 0) await new Promise((r) => setTimeout(r, 5));
      const stopped = await host.stop();
      assert.equal(stopped.abandonedInFlight, 1);
      assert.ok((await pending) instanceof Error);
      await host.start();
      const after = await webhook(portOf(host));
      assert.equal(after.json.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
      assert.equal(calls.failureWrites, 1);
      await host.stop();
      db.close();
    });
});

test('operator route receives pinned identities and a read-only reservation view', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost, calls }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db), {
      operatorReadOnly: { publicOrigin: 'https://operator.example',
        authenticateOwnerRequest: async () => null, verifyCsrf: async () => false,
        rateLimiter: { allow: async () => false },
        issueReadOnlyToken: async () => null },
    }));
    assert.equal(calls.operatorHosts.length, 1);
    const operatorHost = calls.operatorHosts[0];
    assert.deepEqual(Object.keys(operatorHost.conclusionStore), ['getReservation']);
    assert.equal(Object.isFrozen(operatorHost.conclusionStore), true);
    assert.deepEqual([operatorHost.ownerAccountId, operatorHost.repositoryId,
      operatorHost.guardianAppId], [OWNER, REPOSITORY, APP]);
    await host.start();
    const denied = await request(portOf(host), { method: 'POST',
      target: '/guardian/operator/check-reconcile', body: '{}',
      headers: { 'Content-Type': 'application/json', Origin: 'https://operator.example' } });
    assert.notEqual(denied.status, 200);
    assert.equal(calls.failureWrites, 0);
    await host.stop();
    db.close();
  });
});

test('lifecycle state machine rejects concurrent start and never reports activation', async () => {
  await withStubs({}, async ({ createGuardianProtectedHost }) => {
    const db = openDb(':memory:');
    const host = createGuardianProtectedHost(baseConfig(d1(db)));
    assert.equal((await host.stop()).state, 'CREATED');
    const first = host.start();
    await assert.rejects(host.start(), /GUARDIAN_HOST_STATE_INVALID/);
    await first;
    await assert.rejects(host.start(), /GUARDIAN_HOST_STATE_INVALID/);
    const serialized = JSON.stringify(host.status());
    assert.equal(serialized.includes(SECRET), false);
    assert.equal(serialized.includes('PRIVATE KEY'), false);
    assert.equal(host.status().releaseAuthority, 'NOT_ISSUED');
    await host.stop();
    assert.equal((await host.stop()).state, 'STOPPED');
    db.close();
  });
});
