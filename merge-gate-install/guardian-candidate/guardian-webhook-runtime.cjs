/**
 * Inert webhook orchestration for an independently hosted Guardian GitHub App.
 * Importing this module opens no ports and makes no network calls. Even when
 * explicitly enabled later, it only creates FAILURE check runs, never PASS.
 */
'use strict';

const crypto = require('node:crypto');
const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');
const { readAndEvaluateGuardianCandidate } = require('./read-and-evaluate.cjs');
const { mintScopedInstallationToken, postFailureOnlyCheck } =
  require('./github-app-identity.cjs');
const { fetchIndependentlySignedPolicy, GuardianPolicySourceError } =
  require('./independent-policy-source.cjs');

const REPO = 'nohandsai01/test';
const SHA = /^[0-9a-f]{40}$/;
const DELIVERY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_ACTIONS = new Set([
  'opened', 'reopened', 'synchronize', 'ready_for_review',
  'converted_to_draft', 'edited',
]);
const MAX_WEBHOOK_BYTES = 256_000;

function hold(reason, additional = {}) {
  return {
    status: 'SOURCE_ONLY_HOLD', reason, trusted: false,
    activationAllowed: false, authoritativeRequiredCheck: 'NOT_ISSUED',
    ...additional,
  };
}
function record(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function header(headers, key) {
  if (!record(headers)) return null;
  const values = Object.entries(headers).filter(([k]) => k.toLowerCase() === key);
  return values.length === 1 && typeof values[0][1] === 'string' ? values[0][1] : null;
}
function safeEqualsHex(digest, supplied) {
  if (typeof supplied !== 'string' || !/^sha256=[a-f0-9]{64}$/.test(supplied)) {
    return false;
  }
  return crypto.timingSafeEqual(digest, Buffer.from(supplied.slice(7), 'hex'));
}

/** Authenticate raw webhook bytes *before* using any target, SHA or installation ID. */
function verifyWebhook({ rawBody, headers, webhookSecret, trustedInstallationId }) {
  if (!Buffer.isBuffer(rawBody) || !rawBody.length ||
      rawBody.length > MAX_WEBHOOK_BYTES || typeof webhookSecret !== 'string' ||
      webhookSecret.length < 32 || webhookSecret.length > 8192 ||
      !Number.isSafeInteger(trustedInstallationId) || trustedInstallationId <= 0) {
    return { ok: false, reason: 'WEBHOOK_INPUT_OR_HOST_IDENTITY_INVALID' };
  }
  const digest = crypto.createHmac('sha256', webhookSecret).update(rawBody).digest();
  if (!safeEqualsHex(digest, header(headers, 'x-hub-signature-256'))) {
    return { ok: false, reason: 'WEBHOOK_SIGNATURE_INVALID' };
  }
  const event = header(headers, 'x-github-event');
  const deliveryId = header(headers, 'x-github-delivery');
  if (event !== 'pull_request' || !DELIVERY.test(deliveryId || '')) {
    return { ok: false, reason: 'WEBHOOK_EVENT_OR_DELIVERY_NOT_SUPPORTED' };
  }
  let payload;
  try { payload = parseUniqueKeySourceLock(rawBody); } catch (_) {
    return { ok: false, reason: 'WEBHOOK_JSON_INVALID' };
  }
  if (!record(payload) || !ALLOWED_ACTIONS.has(payload.action) ||
      !record(payload.repository) || payload.repository.full_name !== REPO ||
      !record(payload.installation) ||
      payload.installation.id !== trustedInstallationId ||
      !record(payload.pull_request) ||
      payload.number !== payload.pull_request.number ||
      !Number.isSafeInteger(payload.number) || payload.number <= 0 ||
      !record(payload.pull_request.base) ||
      payload.pull_request.base.ref !== 'main' ||
      payload.pull_request.base.repo?.full_name !== REPO ||
      !record(payload.pull_request.head) ||
      payload.pull_request.head.repo?.full_name !== REPO ||
      typeof payload.pull_request.head.sha !== 'string' ||
      !SHA.test(payload.pull_request.head.sha)) {
    return { ok: false, reason: 'WEBHOOK_TARGET_OUT_OF_SCOPE' };
  }
  return { ok: true, deliveryId, installationId: trustedInstallationId,
    pullNumber: payload.number, headSha: payload.pull_request.head.sha };
}

/**
 * Expected host contracts:
 * - `deliveryStore.reserveOnce(id, scope)` is atomic and durable across replicas;
 * - `installationStore.getVerifiedBinding(id)` only reads bindings written
 *   after GitHub App + GitHub owner identity/API verification;
 * - `policyAuthority` hostname, Ed25519 key and SPKI fingerprint are owner
 *   trust configuration, independently administered and never PR-derived;
 * - App key, webhook secret and owner account/repository IDs are host secrets.
 * A missing host dependency always HOLDS, never becomes an in-memory fallback.
 */
async function processGuardianDelivery({ rawBody, headers, host }) {
  if (!record(host)) return hold('GUARDIAN_HOST_CONFIGURATION_UNAVAILABLE');
  const parsed = verifyWebhook({ rawBody, headers,
    webhookSecret: host.webhookSecret,
    trustedInstallationId: host.trustedInstallationId });
  if (!parsed.ok) return hold(parsed.reason);
  if (host.enableFailureCheckWrites !== true ||
      host.founderAuthorizedFailureOnly !== 'EXPLICIT_FAILURE_ONLY') {
    return hold('FEATURE_OFF', { deliveryId: parsed.deliveryId });
  }
  if (!host.deliveryStore || typeof host.deliveryStore.reserveOnce !== 'function' ||
      !host.installationStore ||
      typeof host.installationStore.getVerifiedBinding !== 'function' ||
      !record(host.policyAuthority) ||
      !Number.isSafeInteger(host.guardianAppId) || host.guardianAppId <= 0 ||
      !Number.isSafeInteger(host.expectedOwnerAccountId) ||
      host.expectedOwnerAccountId <= 0 ||
      !Number.isSafeInteger(host.expectedRepositoryId) ||
      host.expectedRepositoryId <= 0 ||
      typeof host.githubAppPrivateKeyPem !== 'string') {
    return hold('HOST_TRUST_OR_DURABLE_REPLAY_STORE_MISSING');
  }

  let binding;
  try {
    binding = await host.installationStore.getVerifiedBinding(parsed.installationId);
  } catch (_) { return hold('INSTALLATION_BINDING_READ_FAILED'); }
  if (!record(binding) || binding.installationId !== parsed.installationId ||
      binding.appId !== host.guardianAppId ||
      binding.ownerAccountId !== host.expectedOwnerAccountId ||
      binding.repositoryId !== host.expectedRepositoryId) {
    return hold('INSTALLATION_BINDING_NOT_VERIFIED');
  }

  // Never process the same delivery on two host replicas. A failed durable
  // reservation may require trusted manual reconciliation, not local retry.
  try {
    if (await host.deliveryStore.reserveOnce(parsed.deliveryId, {
      installationId: parsed.installationId,
      pullNumber: parsed.pullNumber,
      headSha: parsed.headSha,
    }) !== true) {
      return hold('DELIVERY_DUPLICATE_OR_NOT_RESERVED');
    }
  } catch (_) { return hold('DELIVERY_REPLAY_STORE_FAILED'); }

  let policy;
  let policyFailure;
  try {
    policy = await fetchIndependentlySignedPolicy({
      authority: host.policyAuthority,
      pullNumber: parsed.pullNumber, headSha: parsed.headSha,
    });
  } catch (error) {
    policyFailure = error instanceof GuardianPolicySourceError ?
      error.code : 'INDEPENDENT_POLICY_SOURCE_FAILED';
  }

  let installationToken;
  try {
    installationToken = await mintScopedInstallationToken({
      appId: host.guardianAppId,
      installationId: parsed.installationId,
      privateKeyPem: host.githubAppPrivateKeyPem,
      expectedRepositoryId: host.expectedRepositoryId,
    });
  } catch (_) { return hold('GITHUB_APP_INSTALLATION_TOKEN_UNAVAILABLE'); }

  let evidence = hold(policyFailure || 'INDEPENDENT_POLICY_UNAVAILABLE');
  if (policy) {
    try {
      evidence = await readAndEvaluateGuardianCandidate({
        pullNumber: parsed.pullNumber,
        signedPolicyEnvelope: policy.envelope,
        trustedPolicyPublicKeyPem: policy.publicKeyPem,
        githubAppInstallationToken: installationToken.token,
      });
    } catch (_) { evidence = hold('GUARDIAN_EVIDENCE_READ_FAILED'); }
  }
  // This code must never silently grow a success path. The only check-run
  // endpoint invocation is hardwired to conclusion=failure.
  const reason = typeof evidence.reason === 'string' &&
    /^[A-Z0-9_]+$/.test(evidence.reason) ? evidence.reason : 'GUARDIAN_HOLD';
  try {
    const receipt = await postFailureOnlyCheck({ token: installationToken.token,
      headSha: parsed.headSha,
      summary: 'Source-only Guardian candidate: ' + reason +
        '. Independent release authority and Founder activation are not established.',
    });
    return hold('FAILURE_ONLY_CHECK_RECORDED', {
      deliveryId: parsed.deliveryId, checkRunId: receipt.checkRunId,
      evaluatedReason: reason, conclusion: 'failure',
    });
  } catch (_) {
    return hold('FAILURE_ONLY_CHECK_NOT_CONFIRMED', {
      deliveryId: parsed.deliveryId, evaluatedReason: reason,
    });
  }
}

module.exports = { verifyWebhook, processGuardianDelivery };
