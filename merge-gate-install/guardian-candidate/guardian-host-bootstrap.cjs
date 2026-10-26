/**
 * Protected Guardian host bootstrap: strict, fail-closed validation of the
 * owner-supplied host configuration. Importing this module opens no ports,
 * reads no environment, creates no keys and makes no network calls.
 *
 * The bootstrap never re-implements webhook, operator or owner logic. It
 * only pins identities and dependencies once, so the existing handlers are
 * always constructed from one consistent, frozen trust configuration.
 */
'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

const HEX64 = /^[0-9a-f]{64}$/;
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const FORBIDDEN_POLICY_SUFFIXES = Object.freeze(['.github.com',
  '.githubusercontent.com', '.localhost', '.local', '.internal', '.test',
  '.invalid']);
const LOOPBACK = new Set(['127.0.0.1', '::1']);
const DEFAULT_DEPENDENCY_TIMEOUT_MS = 5_000;
const DEFAULT_DRAIN_TIMEOUT_MS = 5_000;
const GUARDIAN_D1_TABLES = Object.freeze([
  'guardian_install_intents',
  'guardian_owner_oauth_states',
  'guardian_installation_bindings',
  'guardian_delivery_receipts',
  'guardian_conclusion_reservations',
]);
const WRITE_MODES = Object.freeze({
  OFF: null,
  FAILURE_ONLY: 'EXPLICIT_FAILURE_ONLY',
  FULL: 'EXPLICIT_FULL_CHECK_WRITES',
});
const TOP_LEVEL = ['listen', 'd1Binding', 'webhook', 'githubApp',
  'policyAuthority', 'checkWrites', 'ownerOnboarding', 'operatorReadOnly',
  'dependencyTimeoutMs', 'drainTimeoutMs'];

class GuardianHostConfigError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GuardianHostConfigError';
    this.code = code;
  }
}
function assert(ok, code) {
  if (!ok) throw new GuardianHostConfigError(code);
}
function record(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function integer(n) { return Number.isSafeInteger(n) && n > 0; }
// Unknown keys are rejected so a misspelled switch never silently defaults.
function exactKeys(o, required, optional = []) {
  if (!record(o)) return false;
  const keys = Object.keys(o);
  return required.every((k) => Object.hasOwn(o, k)) &&
    keys.every((k) => required.includes(k) || optional.includes(k));
}
function boundedMs(value, fallback, min, max) {
  if (value === undefined) return fallback;
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : NaN;
}
function httpsOrigin(raw) {
  if (typeof raw !== 'string' || raw.length > 256) return false;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && u.origin === raw && !u.username &&
      !u.password && !u.search && !u.hash && (u.port === '' || u.port === '443');
  } catch (_) { return false; }
}
function rsaAppKey(pem) {
  if (typeof pem !== 'string' || pem.length > 16_384) return false;
  try {
    const key = crypto.createPrivateKey(pem);
    return key.asymmetricKeyType === 'rsa' &&
      key.asymmetricKeyDetails.modulusLength >= 2048;
  } catch (_) { return false; }
}
function ed25519PublicKey(pem) {
  if (typeof pem !== 'string' || pem.length > 4096) return false;
  try { return crypto.createPublicKey(pem).asymmetricKeyType === 'ed25519'; }
  catch (_) { return false; }
}

function validateListen(listen) {
  assert(exactKeys(listen, ['host', 'port']), 'GUARDIAN_HOST_LISTEN_INVALID');
  // Only loopback: TLS termination, Host pinning and public exposure belong
  // to a separately operated terminator, never to this Node process.
  assert(typeof listen.host === 'string' && LOOPBACK.has(listen.host) &&
    net.isIP(listen.host) !== 0, 'GUARDIAN_HOST_BIND_NOT_LOOPBACK');
  assert(Number.isSafeInteger(listen.port) && listen.port >= 0 &&
    listen.port <= 65535, 'GUARDIAN_HOST_LISTEN_INVALID');
  return Object.freeze({ host: listen.host, port: listen.port });
}

function validateCheckWrites(raw) {
  assert(exactKeys(raw, ['mode'], ['founderGrant']) &&
    Object.hasOwn(WRITE_MODES, raw.mode), 'GUARDIAN_HOST_WRITE_MODE_INVALID');
  const grant = WRITE_MODES[raw.mode];
  // OFF must not carry any grant; an enabled mode needs its exact grant.
  assert(grant === null ? raw.founderGrant === undefined :
    raw.founderGrant === grant, 'GUARDIAN_HOST_WRITE_GRANT_INVALID');
  return Object.freeze({ mode: raw.mode });
}

function validateOwner(raw) {
  assert(exactKeys(raw, ['publicOrigin', 'appSlug', 'clientId', 'clientSecret',
    'authenticateOwnerRequest', 'verifyCsrf', 'rateLimiter']),
  'GUARDIAN_HOST_OWNER_CONFIG_INVALID');
  assert(httpsOrigin(raw.publicOrigin), 'GUARDIAN_HOST_OWNER_ORIGIN_INVALID');
  assert(typeof raw.authenticateOwnerRequest === 'function' &&
    typeof raw.verifyCsrf === 'function' && record(raw.rateLimiter) &&
    typeof raw.rateLimiter.allow === 'function',
  'GUARDIAN_HOST_OWNER_AUTHORITY_MISSING');
  assert(typeof raw.appSlug === 'string' &&
    /^[a-z0-9][a-z0-9-]{1,98}$/.test(raw.appSlug) &&
    typeof raw.clientId === 'string' && /^[A-Za-z0-9._-]{8,128}$/.test(raw.clientId) &&
    typeof raw.clientSecret === 'string' && raw.clientSecret.length >= 32 &&
    raw.clientSecret.length <= 512, 'GUARDIAN_HOST_OWNER_APP_IDENTITY_INVALID');
  return Object.freeze({ ...raw });
}

function validateOperator(raw) {
  assert(exactKeys(raw, ['publicOrigin', 'authenticateOwnerRequest',
    'verifyCsrf', 'rateLimiter', 'issueReadOnlyToken'], ['requestTimeoutMs']),
  'GUARDIAN_HOST_OPERATOR_CONFIG_INVALID');
  assert(httpsOrigin(raw.publicOrigin), 'GUARDIAN_HOST_OPERATOR_ORIGIN_INVALID');
  assert(typeof raw.authenticateOwnerRequest === 'function' &&
    typeof raw.verifyCsrf === 'function' &&
    typeof raw.issueReadOnlyToken === 'function' && record(raw.rateLimiter) &&
    typeof raw.rateLimiter.allow === 'function',
  'GUARDIAN_HOST_OPERATOR_AUTHORITY_MISSING');
  return Object.freeze({ ...raw });
}

/**
 * Returns a frozen configuration or throws GuardianHostConfigError with a
 * code only. Errors never include secrets, PEM data or caller values.
 */
function validateGuardianHostConfig(raw) {
  assert(exactKeys(raw, ['listen', 'd1Binding', 'webhook', 'githubApp',
    'policyAuthority', 'checkWrites'], TOP_LEVEL), 'GUARDIAN_HOST_CONFIG_SHAPE_INVALID');
  const listen = validateListen(raw.listen);
  assert(record(raw.d1Binding) && typeof raw.d1Binding.prepare === 'function',
    'GUARDIAN_HOST_D1_BINDING_MISSING');

  const webhook = raw.webhook;
  assert(exactKeys(webhook, ['secret', 'trustedInstallationId']) &&
    typeof webhook.secret === 'string' && webhook.secret.length >= 32 &&
    webhook.secret.length <= 8192 && integer(webhook.trustedInstallationId),
  'GUARDIAN_HOST_WEBHOOK_IDENTITY_INVALID');

  const app = raw.githubApp;
  assert(exactKeys(app, ['appId', 'privateKeyPem', 'expectedOwnerAccountId',
    'expectedRepositoryId']) && integer(app.appId) &&
    integer(app.expectedOwnerAccountId) && integer(app.expectedRepositoryId),
  'GUARDIAN_HOST_APP_IDENTITY_INVALID');
  assert(rsaAppKey(app.privateKeyPem), 'GUARDIAN_HOST_APP_KEY_INVALID');

  const policy = raw.policyAuthority;
  // Mirrors independent-policy-source.cjs so a host the runtime would refuse
  // per delivery is refused once at boot instead of silently holding.
  assert(exactKeys(policy, ['hostname', 'publicKeyPem', 'pinnedSpkiSha256']) &&
    typeof policy.hostname === 'string' && HOSTNAME.test(policy.hostname) &&
    net.isIP(policy.hostname) === 0 && policy.hostname !== 'api.github.com' &&
    !FORBIDDEN_POLICY_SUFFIXES.some((s) => policy.hostname.endsWith(s)) &&
    typeof policy.pinnedSpkiSha256 === 'string' &&
    HEX64.test(policy.pinnedSpkiSha256) && ed25519PublicKey(policy.publicKeyPem),
  'GUARDIAN_HOST_POLICY_AUTHORITY_INVALID');
  // The pinned fingerprint must describe the configured key itself.
  const spki = crypto.createPublicKey(policy.publicKeyPem)
    .export({ type: 'spki', format: 'der' });
  assert(crypto.createHash('sha256').update(spki).digest('hex') ===
    policy.pinnedSpkiSha256, 'GUARDIAN_HOST_POLICY_FINGERPRINT_MISMATCH');

  const checkWrites = validateCheckWrites(raw.checkWrites);
  const ownerOnboarding = raw.ownerOnboarding === undefined ? null :
    validateOwner(raw.ownerOnboarding);
  const operatorReadOnly = raw.operatorReadOnly === undefined ? null :
    validateOperator(raw.operatorReadOnly);
  const dependencyTimeoutMs = boundedMs(raw.dependencyTimeoutMs,
    DEFAULT_DEPENDENCY_TIMEOUT_MS, 50, 30_000);
  const drainTimeoutMs = boundedMs(raw.drainTimeoutMs,
    DEFAULT_DRAIN_TIMEOUT_MS, 0, 60_000);
  assert(Number.isSafeInteger(dependencyTimeoutMs) &&
    Number.isSafeInteger(drainTimeoutMs), 'GUARDIAN_HOST_TIMEOUT_INVALID');

  return Object.freeze({
    listen, d1Binding: raw.d1Binding,
    webhook: Object.freeze({ ...webhook }),
    githubApp: Object.freeze({ ...app }),
    policyAuthority: Object.freeze({ ...policy }),
    checkWrites, ownerOnboarding, operatorReadOnly,
    dependencyTimeoutMs, drainTimeoutMs,
  });
}

/**
 * Read-only schema presence probe on the injected D1 binding. It never
 * creates, migrates or writes; a missing table or uncertain read HOLDS.
 */
async function probeGuardianD1Schema(d1Binding) {
  for (const table of GUARDIAN_D1_TABLES) {
    let row;
    try {
      row = await d1Binding.prepare('SELECT 1 AS present FROM ' + table +
        ' LIMIT 1').bind().first();
    } catch (_) {
      throw new GuardianHostConfigError('GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE');
    }
    assert(row === null || (record(row) && row.present === 1),
      'GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE');
  }
  return true;
}

module.exports = { validateGuardianHostConfig, probeGuardianD1Schema,
  GuardianHostConfigError, GUARDIAN_D1_TABLES };
