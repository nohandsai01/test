/**
 * Isolated Guardian protected-host bootstrap and runtime adapter.
 *
 * Wraps the existing, unmodified guardian-http-server handler with host
 * lifecycle (start / stop / restart), strict configuration, startup probes of
 * the injected D1 binding and GitHub App identity, and dependency-fault
 * isolation. It does not re-implement webhook verification, Check publication,
 * operator reconciliation or owner onboarding.
 *
 * Importing this module opens no port and performs no I/O. Nothing here
 * provisions D1, installs a GitHub App, creates keys or activates a feature.
 * The host binds to loopback only; TLS termination and public exposure are a
 * separate owner-operated component.
 */
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const appIdentity = require('./github-app-identity.cjs');
const { createGuardianHttpServer } = require('./guardian-http-server.cjs');
const { createGuardianD1Stores } = require('./guardian-d1-stores.cjs');

const MODE_GRANTS = Object.freeze({
  FAILURE_ONLY: 'EXPLICIT_FAILURE_ONLY',
  FULL: 'EXPLICIT_FULL_CHECK_WRITES',
});
const LOOPBACK = new Set(['127.0.0.1', '::1']);
const WEBHOOK_TABLES = ['guardian_installation_bindings',
  'guardian_delivery_receipts', 'guardian_conclusion_reservations'];
const ONBOARDING_TABLES = ['guardian_install_intents',
  'guardian_owner_oauth_states'];
const CONFIG_KEYS = new Set(['listenAddress', 'port', 'mode', 'modeGrant',
  'guardianAppId', 'trustedInstallationId', 'expectedOwnerAccountId',
  'expectedRepositoryId', 'webhookSecret', 'githubAppPrivateKeyPem',
  'policyAuthority', 'd1Binding', 'startupTimeoutMs', 'drainTimeoutMs',
  'dependencyFaultThreshold', 'operatorReadOnly', 'ownerOnboarding']);
const OPERATOR_KEYS = new Set(['publicOrigin', 'authenticateOwnerRequest',
  'verifyCsrf', 'rateLimiter', 'issueReadOnlyToken', 'requestTimeoutMs']);
const ONBOARDING_KEYS = new Set(['publicOrigin', 'appSlug', 'redirectUri',
  'clientId', 'clientSecret', 'authenticateOwnerRequest', 'verifyCsrf',
  'rateLimiter']);
// D1 integrity failures latch HOLD immediately; plain I/O failures count
// toward the consecutive-fault threshold.
const INTEGRITY_FAULT = /READBACK_INVALID|RECORD_INVALID|ROW_INVALID|RESULT_UNVERIFIED|READ_INVALID|PREPARE_INVALID/;

class GuardianHostError extends Error {
  constructor(code, field) {
    super(field ? code + ':' + field : code);
    this.name = 'GuardianHostError';
    this.code = code;
    if (field) this.field = field;
  }
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function boundedInteger(value, min, max, fallback) {
  if (value === undefined) return fallback;
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : NaN;
}
function requireConfig(ok, field) {
  if (!ok) throw new GuardianHostError('GUARDIAN_HOST_CONFIG_INVALID', field);
}
function exactKeys(object, allowed) {
  return record(object) && Object.keys(object).every((key) => allowed.has(key));
}

function validateAppKey(pem) {
  requireConfig(typeof pem === 'string' && pem.length > 100 && pem.length < 20_000,
    'githubAppPrivateKeyPem');
  let key;
  try { key = crypto.createPrivateKey(pem); } catch (_) { key = null; }
  requireConfig(key && key.asymmetricKeyType === 'rsa' &&
    key.asymmetricKeyDetails.modulusLength >= 2048, 'githubAppPrivateKeyPem');
}

function validatePolicyAuthority(authority) {
  requireConfig(exactKeys(authority, new Set(['hostname', 'publicKeyPem',
    'pinnedSpkiSha256'])) && typeof authority.hostname === 'string' &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(authority.hostname) &&
    typeof authority.publicKeyPem === 'string' &&
    typeof authority.pinnedSpkiSha256 === 'string' &&
    /^[0-9a-f]{64}$/.test(authority.pinnedSpkiSha256), 'policyAuthority');
  let key;
  try { key = crypto.createPublicKey(authority.publicKeyPem); } catch (_) { key = null; }
  requireConfig(key && key.asymmetricKeyType === 'ed25519', 'policyAuthority');
  const actual = crypto.createHash('sha256')
    .update(key.export({ format: 'der', type: 'spki' })).digest();
  requireConfig(crypto.timingSafeEqual(actual,
    Buffer.from(authority.pinnedSpkiSha256, 'hex')), 'policyAuthority');
}

function validateConfig(config) {
  requireConfig(record(config), 'config');
  for (const key of Object.keys(config)) requireConfig(CONFIG_KEYS.has(key), key);
  requireConfig(LOOPBACK.has(config.listenAddress), 'listenAddress');
  requireConfig(Number.isSafeInteger(config.port) && config.port >= 0 &&
    config.port <= 65535, 'port');
  requireConfig(['OFF', 'FAILURE_ONLY', 'FULL'].includes(config.mode), 'mode');
  requireConfig(config.mode === 'OFF' ? config.modeGrant === undefined :
    config.modeGrant === MODE_GRANTS[config.mode], 'modeGrant');
  for (const field of ['guardianAppId', 'trustedInstallationId',
    'expectedOwnerAccountId', 'expectedRepositoryId']) {
    requireConfig(positive(config[field]), field);
  }
  requireConfig(typeof config.webhookSecret === 'string' &&
    config.webhookSecret.length >= 32 && config.webhookSecret.length <= 8192 &&
    /^[\x21-\x7e]+$/.test(config.webhookSecret), 'webhookSecret');
  validateAppKey(config.githubAppPrivateKeyPem);
  validatePolicyAuthority(config.policyAuthority);
  requireConfig(record(config.d1Binding) &&
    typeof config.d1Binding.prepare === 'function', 'd1Binding');
  const timing = {
    startupTimeoutMs: boundedInteger(config.startupTimeoutMs, 100, 30_000, 5000),
    drainTimeoutMs: boundedInteger(config.drainTimeoutMs, 0, 30_000, 5000),
    dependencyFaultThreshold: boundedInteger(config.dependencyFaultThreshold, 1, 20, 3),
  };
  for (const [field, value] of Object.entries(timing)) {
    requireConfig(!Number.isNaN(value), field);
  }
  if (config.operatorReadOnly !== undefined) {
    requireConfig(exactKeys(config.operatorReadOnly, OPERATOR_KEYS), 'operatorReadOnly');
  }
  if (config.ownerOnboarding !== undefined) {
    requireConfig(exactKeys(config.ownerOnboarding, ONBOARDING_KEYS), 'ownerOnboarding');
  }
  return timing;
}

function withDeadline(promise, ms, code) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new GuardianHostError(code)), ms);
  });
  return Promise.race([Promise.resolve().then(() => promise), deadline])
    .finally(() => clearTimeout(timer));
}

function sendHold(res, reason) {
  if (res.headersSent) return;
  const body = JSON.stringify({ status: 'SOURCE_ONLY_HOLD', reason,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
  res.writeHead(503, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
  });
  res.end(body);
}

/**
 * Validates configuration synchronously and returns an inert host object.
 * No port is opened and no D1/GitHub I/O occurs until start().
 */
function createGuardianProtectedHost(config) {
  const timing = validateConfig(config);
  const rawStores = createGuardianD1Stores(config.d1Binding);

  let state = 'CREATED';
  let dependencyHold = null;
  let consecutiveFaults = 0;
  const inFlight = new Set();

  function noteFault(error) {
    const code = typeof error?.code === 'string' ? error.code : 'GUARDIAN_D1_FAULT';
    consecutiveFaults++;
    if (!dependencyHold && (INTEGRITY_FAULT.test(code) ||
        consecutiveFaults >= timing.dependencyFaultThreshold)) {
      dependencyHold = INTEGRITY_FAULT.test(code) ?
        'GUARDIAN_HOST_D1_INTEGRITY_HOLD' : 'GUARDIAN_HOST_D1_FAULT_HOLD';
    }
  }
  function guard(store, methods) {
    const wrapped = {};
    for (const name of methods) {
      wrapped[name] = async (...args) => {
        try {
          const result = await store[name](...args);
          consecutiveFaults = 0;
          return result;
        } catch (error) {
          noteFault(error);
          throw error;
        }
      };
    }
    return Object.freeze(wrapped);
  }
  const stores = Object.freeze({
    installationStore: guard(rawStores.installationStore,
      ['getVerifiedBinding', 'bindVerifiedOnce']),
    deliveryStore: guard(rawStores.deliveryStore, ['reserveOnce']),
    conclusionStore: guard(rawStores.conclusionStore,
      ['reserveOnce', 'getReservation']),
    intentStore: guard(rawStores.intentStore,
      ['putIfAbsent', 'consumeIfOwnerAndUnexpired']),
    oauthStore: guard(rawStores.oauthStore, ['putIfAbsent', 'takeOnce']),
  });

  const fullMode = config.mode === 'FULL';
  const failureOnly = config.mode === 'FAILURE_ONLY';
  const innerHost = {
    webhookSecret: config.webhookSecret,
    trustedInstallationId: config.trustedInstallationId,
    guardianAppId: config.guardianAppId,
    expectedOwnerAccountId: config.expectedOwnerAccountId,
    expectedRepositoryId: config.expectedRepositoryId,
    githubAppPrivateKeyPem: config.githubAppPrivateKeyPem,
    policyAuthority: Object.freeze({ ...config.policyAuthority }),
    installationStore: stores.installationStore,
    deliveryStore: stores.deliveryStore,
    conclusionStore: stores.conclusionStore,
    enableFailureCheckWrites: failureOnly,
    founderAuthorizedFailureOnly: failureOnly ? config.modeGrant : null,
    enableFullCheckWrites: fullMode,
    founderAuthorizedFullMode: fullMode ? config.modeGrant : null,
    enableOwnerReconciliation: false,
    enableReadOnlyOperatorRoutes: config.operatorReadOnly !== undefined,
    operatorReadOnly: config.operatorReadOnly === undefined ? undefined :
      Object.freeze({ ...config.operatorReadOnly,
        ownerAccountId: config.expectedOwnerAccountId,
        repositoryId: config.expectedRepositoryId,
        guardianAppId: config.guardianAppId,
        // Read-only view: the operator route can never reserve a conclusion.
        conclusionStore: Object.freeze({
          getReservation: stores.conclusionStore.getReservation }) }),
    enableOwnerOnboardingRoutes: config.ownerOnboarding !== undefined,
    ownerOnboarding: config.ownerOnboarding === undefined ? undefined :
      Object.freeze({ ...config.ownerOnboarding,
        appId: config.guardianAppId,
        expectedOwnerAccountId: config.expectedOwnerAccountId,
        privateKeyPem: config.githubAppPrivateKeyPem,
        intentStore: stores.intentStore, oauthStore: stores.oauthStore,
        installationStore: stores.installationStore }),
  };

  let inner;
  try {
    inner = createGuardianHttpServer({ host: Object.freeze(innerHost) });
  } catch (_) {
    throw new GuardianHostError('GUARDIAN_HOST_CONFIG_INVALID',
      config.operatorReadOnly !== undefined ? 'operatorReadOnly' : 'ownerOnboarding');
  }
  const [innerHandler] = inner.listeners('request');
  if (typeof innerHandler !== 'function') {
    throw new GuardianHostError('GUARDIAN_HOST_CONFIG_INVALID', 'httpServer');
  }

  const server = http.createServer((req, res) => {
    if (state !== 'RUNNING' || dependencyHold) {
      req.resume();
      return sendHold(res, dependencyHold || 'GUARDIAN_HOST_NOT_RUNNING');
    }
    const done = new Promise((resolve) => res.once('close', resolve));
    inFlight.add(done);
    done.then(() => inFlight.delete(done));
    Promise.resolve().then(() => innerHandler(req, res)).catch(() =>
      sendHold(res, 'GUARDIAN_HOST_UNHANDLED_ERROR'));
  });
  server.requestTimeout = inner.requestTimeout;
  server.headersTimeout = inner.headersTimeout;
  server.keepAliveTimeout = inner.keepAliveTimeout;
  server.maxRequestsPerSocket = inner.maxRequestsPerSocket;

  async function probeDependencies() {
    const tables = config.ownerOnboarding !== undefined ?
      [...WEBHOOK_TABLES, ...ONBOARDING_TABLES] : WEBHOOK_TABLES;
    for (const table of tables) {
      try {
        const row = await config.d1Binding.prepare(
          'SELECT 1 AS present FROM ' + table + ' LIMIT 1').bind().first();
        if (row !== null && !record(row)) throw new Error('unexpected row');
      } catch (_) {
        throw new GuardianHostError('GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE');
      }
    }
    if (config.mode === 'OFF') return;
    let binding;
    try {
      binding = await rawStores.installationStore.getVerifiedBinding(
        config.trustedInstallationId);
    } catch (_) { binding = null; }
    if (!record(binding) || binding.installationId !== config.trustedInstallationId ||
        binding.appId !== config.guardianAppId ||
        binding.ownerAccountId !== config.expectedOwnerAccountId ||
        binding.repositoryId !== config.expectedRepositoryId) {
      throw new GuardianHostError('GUARDIAN_HOST_INSTALLATION_BINDING_UNVERIFIED');
    }
    try {
      // Point-in-time identity proof; the token is discarded, never stored.
      const minted = await appIdentity.mintScopedInstallationToken({
        appId: config.guardianAppId, installationId: config.trustedInstallationId,
        privateKeyPem: config.githubAppPrivateKeyPem,
        expectedRepositoryId: config.expectedRepositoryId,
        requireActionsRead: fullMode,
      });
      await appIdentity.revalidateCurrentInstallationScope({
        appId: config.guardianAppId, installationId: config.trustedInstallationId,
        privateKeyPem: config.githubAppPrivateKeyPem,
        installationToken: minted.token,
        expectedOwnerAccountId: config.expectedOwnerAccountId,
        expectedRepositoryId: config.expectedRepositoryId,
        requireActionsRead: fullMode,
      });
    } catch (_) {
      throw new GuardianHostError('GUARDIAN_HOST_GITHUB_IDENTITY_UNVERIFIED');
    }
  }

  function listen() {
    return new Promise((resolve, reject) => {
      const onError = () => reject(new GuardianHostError('GUARDIAN_HOST_LISTEN_FAILED'));
      server.once('error', onError);
      server.listen(config.port, config.listenAddress, () => {
        server.removeListener('error', onError);
        resolve();
      });
    });
  }
  function closeListener() {
    return new Promise((resolve) => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
      server.closeIdleConnections();
    });
  }

  function status() {
    const address = server.listening ? server.address() : null;
    return Object.freeze({
      state, mode: config.mode,
      dependencyHold: dependencyHold !== null,
      holdReason: dependencyHold,
      inFlight: inFlight.size,
      address: address ? Object.freeze({ address: address.address, port: address.port }) : null,
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  }

  async function start() {
    if (!['CREATED', 'STOPPED', 'FAILED'].includes(state)) {
      throw new GuardianHostError('GUARDIAN_HOST_STATE_INVALID');
    }
    state = 'STARTING';
    try {
      await withDeadline(probeDependencies(), timing.startupTimeoutMs,
        'GUARDIAN_HOST_STARTUP_TIMEOUT');
      await listen();
    } catch (error) {
      state = 'FAILED';
      await closeListener();
      throw error instanceof GuardianHostError ? error :
        new GuardianHostError('GUARDIAN_HOST_STARTUP_FAILED');
    }
    // Only a fully successful re-probe clears a latched dependency HOLD.
    dependencyHold = null;
    consecutiveFaults = 0;
    state = 'RUNNING';
    return status();
  }

  async function stop() {
    if (['CREATED', 'STOPPED', 'FAILED'].includes(state)) return status();
    if (state !== 'RUNNING') throw new GuardianHostError('GUARDIAN_HOST_STATE_INVALID');
    state = 'STOPPING';
    const closed = closeListener();
    let abandoned = 0;
    if (inFlight.size) {
      try {
        await withDeadline(Promise.all([...inFlight]), timing.drainTimeoutMs,
          'GUARDIAN_HOST_DRAIN_TIMEOUT');
      } catch (_) {
        // Sockets are closed, but an in-progress handler may still finish its
        // durable D1 reservation; that reservation blocks any re-publication.
        abandoned = inFlight.size;
        server.closeAllConnections();
      }
    }
    await closed;
    state = 'STOPPED';
    return Object.freeze({ ...status(), abandonedInFlight: abandoned });
  }

  async function restart() {
    await stop();
    return start();
  }

  return Object.freeze({ start, stop, restart, status });
}

async function bootstrapGuardianProtectedHost(config) {
  const host = createGuardianProtectedHost(config);
  await host.start();
  return host;
}

module.exports = { createGuardianProtectedHost, bootstrapGuardianProtectedHost,
  GuardianHostError };
