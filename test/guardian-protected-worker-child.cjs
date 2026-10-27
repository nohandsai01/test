'use strict';
// Real isolated child-side Protected Host + Supervisor, OFF mode only.
// This is a test entrypoint, never a production launcher. The parent does
// not supply any secret or Host configuration over argv/environment/IPC.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { createGuardianHostProcessRunner } = require(
  '../merge-gate-install/guardian-candidate/guardian-host-process-runner.cjs');
const { createGuardianChildRuntime } = require(
  '../merge-gate-install/guardian-candidate/guardian-child-runtime.cjs');

const db = new DatabaseSync(':memory:');
db.exec(fs.readFileSync(path.join(__dirname,
  '../merge-gate-install/guardian-candidate/guardian-d1-schema.sql'), 'utf8'));
const appKey = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
}).privateKey.export({ type: 'pkcs8', format: 'pem' });
const policyPublic = crypto.generateKeyPairSync('ed25519').publicKey;
const pub = policyPublic.export({ format: 'pem', type: 'spki' });
const digest = crypto.createHash('sha256')
  .update(policyPublic.export({ format: 'der', type: 'spki' })).digest('hex');
const protectedHostConfig = {
  listenAddress: '127.0.0.1', port: 0,
  mode: 'OFF',
  guardianAppId: 999, trustedInstallationId: 42,
  expectedOwnerAccountId: 100, expectedRepositoryId: 88,
  webhookSecret: 'synthetic-fixture-secret-' + 'x'.repeat(36),
  githubAppPrivateKeyPem: appKey,
  policyAuthority: { hostname: 'policy.example.com',
    publicKeyPem: pub, pinnedSpkiSha256: digest },
  d1Binding: { prepare(sql) {
    const prepared = db.prepare(sql);
    return { bind(...params) {
      return {
        async first() { return prepared.get(...params) ?? null; },
        async run() {
          const result = prepared.run(...params);
          return { success: true, meta: { changes: Number(result.changes) } };
        },
      };
    } };
  } },
};
const runtime = createGuardianChildRuntime({
  createRunner: ({ onTerminal }) => createGuardianHostProcessRunner({
    protectedHostConfig, onTerminal, signalSource: process,
    stopDeadlineMs: 500,
  }),
  ipc: process,
  healthTimeoutMs: 1500,
});
runtime.start().catch(() => {
  // A failed child must NOT signal READY or generate an authorized Check.
  process.exitCode = 1;
  try { if (process.connected) process.disconnect(); } catch (_) {}
});
