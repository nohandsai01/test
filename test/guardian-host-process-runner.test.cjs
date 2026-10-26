'use strict';
// Real existing Protected Host composed with Supervisor in source-only OFF mode.
// Synthetic RSA/Ed25519 key fixtures, temporary SQLite and loopback only.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { DatabaseSync } = require('node:sqlite');
const { createGuardianHostProcessRunner } = require(
  '../merge-gate-install/guardian-candidate/guardian-host-process-runner.cjs');

const DIR = path.join(__dirname, '../merge-gate-install/guardian-candidate');
const SCHEMA = fs.readFileSync(path.join(DIR, 'guardian-d1-schema.sql'), 'utf8');
const appPrivateKey = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
}).privateKey.export({ format: 'pem', type: 'pkcs8' });
const policy = crypto.generateKeyPairSync('ed25519').publicKey;
const policyPem = policy.export({ format: 'pem', type: 'spki' });
const policyPin = crypto.createHash('sha256')
  .update(policy.export({ format: 'der', type: 'spki' })).digest('hex');

function fixture({ missingSchema = false } = {}) {
  const db = new DatabaseSync(':memory:');
  if (!missingSchema) db.exec(SCHEMA);
  const config = {
    listenAddress: '127.0.0.1', port: 0,
    mode: 'OFF', guardianAppId: 999, trustedInstallationId: 42,
    expectedOwnerAccountId: 100, expectedRepositoryId: 88,
    webhookSecret: 'synthetic-secret-' + 'z'.repeat(40),
    githubAppPrivateKeyPem: appPrivateKey,
    policyAuthority: {
      hostname: 'policy.example.com', publicKeyPem: policyPem,
      pinnedSpkiSha256: policyPin,
    },
    d1Binding: {
      prepare(sql) {
        const statement = db.prepare(sql);
        return {
          bind(...args) {
            return {
              async first() { return statement.get(...args) ?? null; },
              async run() {
                const result = statement.run(...args);
                return { success: true,
                  meta: { changes: Number(result.changes) } };
              },
            };
          },
        };
      },
    },
  };
  const signals = new EventEmitter(), reports = [];
  let announce;
  const terminal = new Promise((resolve) => { announce = resolve; });
  const create = () => createGuardianHostProcessRunner({
    protectedHostConfig: config,
    signalSource: signals,
    onTerminal: (receipt) => {
      reports.push(receipt);
      announce(receipt);
    },
    stopDeadlineMs: 500,
  });
  return { config, db, signals, reports, terminal, create };
}
function health(port) {
  return new Promise((resolve, reject) => {
    const request = http.get({
      hostname: '127.0.0.1', port, path: '/healthz',
    }, (response) => {
      let text = '';
      response.on('data', (value) => { text += value; });
      response.on('end', () => {
        try { resolve({ code: response.statusCode, body: JSON.parse(text) }); }
        catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
  });
}

test('explicit composition is inert, frozen and has no raw Host/credential getter', async () => {
  const f = fixture();
  try {
    const runner = f.create();
    assert.ok(Object.isFrozen(runner));
    assert.deepEqual(Object.keys(runner).sort(), ['start', 'status', 'stop']);
    assert.equal(runner.status().state, 'CREATED');
    assert.equal(runner.status().activationAllowed, false);
    assert.equal(f.signals.listenerCount('SIGTERM'), 0);
    assert.equal(f.signals.listenerCount('SIGINT'), 0);
    assert.equal(runner.status().underlyingHostState, 'CREATED');
    assert.equal(f.reports.length, 0);
  } finally { f.db.close(); }
});

test('actual protected OFF Host launches loopback, then stops cleanly on SIGTERM', async () => {
  const f = fixture();
  const runner = f.create();
  try {
    const active = await runner.start();
    assert.equal(active.state, 'RUNNING');
    assert.equal(active.activationAllowed, false);
    assert.equal(active.releaseAuthority, 'NOT_ISSUED');
    const underlying = active.underlyingHostState;
    assert.equal(underlying, 'RUNNING');
    assert.equal(f.signals.listenerCount('SIGTERM'), 1);
    assert.equal(f.signals.listenerCount('SIGINT'), 1);

    assert.equal(active.loopback.address, '127.0.0.1');
    assert.ok(active.loopback.port > 0);
    const check = await health(active.loopback.port);
    assert.equal(check.code, 200);
    assert.equal(check.body.feature, 'OFF_OR_SOURCE_ONLY');
    assert.equal(check.body.releaseAuthority, 'NOT_ISSUED');
    f.signals.emit('SIGTERM');
    const receipt = await f.terminal;
    assert.equal(receipt.state, 'STOPPED');
    assert.equal(receipt.reason, 'SIGTERM');
    assert.equal(receipt.hostStopped, true);
    assert.equal(receipt.activationAllowed, false);
    assert.equal(receipt.releaseAuthority, 'NOT_ISSUED');
    assert.equal(runner.status().state, 'STOPPED');
    assert.equal(f.signals.listenerCount('SIGTERM'), 0);
    assert.equal(f.signals.listenerCount('SIGINT'), 0);
  } finally {
    await runner.stop();
    f.db.close();
  }
});

test('missing actual D1 schema never opens a listener or claims RUNNING', async () => {
  const f = fixture({ missingSchema: true });
  const runner = f.create();
  try {
    await assert.rejects(runner.start(),
      { code: 'GUARDIAN_SUPERVISOR_START_FAILED' });
    const terminal = await f.terminal;
    assert.equal(terminal.state, 'FAILED');
    assert.equal(terminal.hostStopped, false);
    assert.equal(runner.status().activationAllowed, false);
    assert.equal(runner.status().underlyingHostState, 'FAILED');
    assert.equal(f.signals.listenerCount('SIGTERM'), 0);
  } finally { f.db.close(); }
});

test('invalid protected config fails before registering signals or touching D1', () => {
  const f = fixture();
  try {
    f.config.listenAddress = '0.0.0.0';
    assert.throws(f.create, /GUARDIAN_HOST_CONFIG_INVALID/);
    assert.equal(f.signals.listenerCount('SIGTERM'), 0);
    assert.equal(f.reports.length, 0);
  } finally { f.db.close(); }
});

test('runner rejects unexpected injection keys and never exposes writer', () => {
  const f = fixture();
  try {
    assert.throws(() => createGuardianHostProcessRunner({
      protectedHostConfig: f.config,
      onTerminal() {},
      checkWriter: () => {},
    }), /GUARDIAN_PROCESS_RUNNER_CONFIG_INVALID/);
    const runner = f.create();
    assert.equal(Object.hasOwn(runner, 'reserveOnce'), false);
    assert.equal(Object.hasOwn(runner, 'postCheck'), false);
    assert.equal(Object.hasOwn(runner, 'restart'), false);
  } finally { f.db.close(); }
});
