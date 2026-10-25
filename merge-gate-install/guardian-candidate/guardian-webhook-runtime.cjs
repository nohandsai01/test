/**
 * Inert webhook orchestration for an independently hosted Guardian GitHub App.
 * Importing this module opens no ports and makes no network calls. Even when
 * Default OFF. Full SUCCESS/FAILURE mode is a separate, explicit host opt-in
 * requiring independent signed policy, review/workflow/ruleset provenance.
 */
'use strict';

const crypto = require('node:crypto');
const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');
const { readAndEvaluateGuardianCandidate } = require('./read-and-evaluate.cjs');
const { readGuardianGithubJson } = require('./github-rest-collector.cjs');
const { mintScopedInstallationToken, postFailureOnlyCheck,
  postConclusiveSuccessCheck,
  revalidateCurrentInstallationScope } =
  require('./github-app-identity.cjs');
const { verifySignedPolicy } = require('./signed-policy.cjs');
const { fetchIndependentlySignedPolicy, GuardianPolicySourceError } =
  require('./independent-policy-source.cjs');

const REPO = 'nohandsai01/test';
const SHA = /^[0-9a-f]{40}$/;
const DELIVERY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_ACTIONS = new Set([
  'opened', 'reopened', 'synchronize', 'ready_for_review',
  'converted_to_draft', 'edited',
]);
const REVIEW_ACTIONS = new Set(['submitted', 'dismissed', 'edited']);
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
  if (!['pull_request', 'pull_request_review', 'workflow_run'].includes(event) ||
      !DELIVERY.test(deliveryId || '')) {
    return { ok: false, reason: 'WEBHOOK_EVENT_OR_DELIVERY_NOT_SUPPORTED' };
  }
  let payload;
  try { payload = parseUniqueKeySourceLock(rawBody); } catch (_) {
    return { ok: false, reason: 'WEBHOOK_JSON_INVALID' };
  }
  if (!record(payload) ||
      !(event === 'pull_request' ? ALLOWED_ACTIONS.has(payload.action) :
        event === 'pull_request_review' ? REVIEW_ACTIONS.has(payload.action) :
          payload.action === 'completed') ||
      !record(payload.repository) || payload.repository.full_name !== REPO ||
      !record(payload.installation) ||
      payload.installation.id !== trustedInstallationId) {
    return { ok: false, reason: 'WEBHOOK_TARGET_OUT_OF_SCOPE' };
  }
  // A workflow_run webhook has a different GitHub payload shape. GitHub
  // Actions push runs may have no linked PR; those cannot be guessed.
  if (event === 'workflow_run') {
    const run = payload.workflow_run;
    const pulls = run?.pull_requests;
    if (!record(run) || !SHA.test(run.head_sha || '') ||
        !Array.isArray(pulls) || pulls.length !== 1 ||
        !Number.isSafeInteger(pulls[0]?.number) || pulls[0].number <= 0 ||
        (run.conclusion !== 'success' && run.conclusion !== 'failure')) {
      return { ok: false, reason: 'WEBHOOK_WORKFLOW_PR_UNBOUND' };
    }
    return { ok: true, deliveryId, installationId: trustedInstallationId,
      pullNumber: pulls[0].number, headSha: run.head_sha };
  }
  const pr = payload.pull_request;
  if (!record(pr) || (event === 'pull_request' && payload.number !== pr.number) ||
      !Number.isSafeInteger(pr.number) || pr.number <= 0 ||
      !record(pr.base) || pr.base.ref !== 'main' ||
      pr.base.repo?.full_name !== REPO || !record(pr.head) ||
      pr.head.repo?.full_name !== REPO ||
      typeof pr.head.sha !== 'string' || !SHA.test(pr.head.sha)) {
    return { ok: false, reason: 'WEBHOOK_TARGET_OUT_OF_SCOPE' };
  }
  // A review event can arrive after a newer push. The authenticated review
  // must bind to the same immutable commit as the event's PR head, otherwise
  // it must not consume a durable delivery or trigger any Check.
  if (event === 'pull_request_review' &&
      (!record(payload.review) ||
       !['approved', 'changes_requested', 'commented', 'dismissed'].includes(
         payload.review.state) ||
       payload.review.commit_id !== pr.head.sha)) {
    return { ok: false, reason: 'WEBHOOK_REVIEW_EXACT_HEAD_UNVERIFIED' };
  }
  return { ok: true, deliveryId, installationId: trustedInstallationId,
    pullNumber: pr.number, headSha: pr.head.sha };
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
  return processVerifiedGuardianTarget(parsed, host);
}

/**
 * For a trusted owner scheduler when push-based workflow_run events contain no
 * linked PR. The caller MUST be an independently authenticated owner runtime;
 * this method has no HTTP route and defaults OFF. PR number/SHA are still
 * checked against the signed remote policy and fresh GitHub REST evidence.
 */
async function processGuardianReconciliation({ pullNumber, headSha, host,
  operatorSession }) {
  if (!record(host) || host.enableOwnerReconciliation !== true ||
      host.ownerReconciliationGrant !== 'EXPLICIT_OWNER_RECONCILIATION' ||
      typeof host.authorizeReconciliation !== 'function' ||
      !host.reconciliationRateLimiter ||
      typeof host.reconciliationRateLimiter.allow !== 'function' ||
      !Number.isSafeInteger(pullNumber) || pullNumber <= 0 ||
      !SHA.test(headSha || '') ||
      !Number.isSafeInteger(host.trustedInstallationId) ||
      host.trustedInstallationId <= 0) {
    return hold('OWNER_RECONCILIATION_OFF_OR_INVALID');
  }
  try {
    if (await host.authorizeReconciliation({ operatorSession, pullNumber,
      headSha }) !== true ||
        await host.reconciliationRateLimiter.allow({ pullNumber, headSha }) !== true) {
      return hold('OWNER_RECONCILIATION_NOT_AUTHORIZED');
    }
  } catch (_) { return hold('OWNER_RECONCILIATION_AUTHORITY_UNVERIFIED'); }
  return processVerifiedGuardianTarget({
    deliveryId: crypto.randomUUID(),
    installationId: host.trustedInstallationId, pullNumber, headSha,
  }, host);
}

/**
 * Last-mile check target guard. Even valid signed webhook bytes can be stale
 * by the time the independent host posts a Check. This reads the live PR from
 * GitHub using the separately minted repository-scoped installation token.
 * No target identifier or hostname from the webhook is used as an HTTP URL.
 */
async function freshCurrentTarget(parsed, host, token) {
  try {
    const response = await readGuardianGithubJson('/repos/nohandsai01/test/pulls/' +
      parsed.pullNumber, token);
    const pr = response.body;
    return !response.link && record(pr) && pr.number === parsed.pullNumber &&
      pr.state === 'open' && pr.draft === false &&
      record(pr.base) && pr.base.ref === 'main' &&
      record(pr.base.repo) &&
      pr.base.repo.full_name === REPO &&
      pr.base.repo.id === host.expectedRepositoryId &&
      record(pr.head) && pr.head.sha === parsed.headSha &&
      record(pr.head.repo) && pr.head.repo.full_name === REPO &&
      pr.head.repo.id === host.expectedRepositoryId;
  } catch (_) {
    return false;
  }
}

/**
 * Exactly one check publication attempt per repository/PR/head, across ALL
 * configured write modes and concurrent delivery IDs. No in-memory fallback:
 * the unique persistent D1 constraint is the final authority for reservation.
 * Failed or uncertain reservations are permanent HOLDs, never auto-retried.
 */
async function reserveAndRecheckConclusion(parsed, host, token) {
  if (!(await freshCurrentTarget(parsed, host, token))) {
    return hold('FRESH_PR_TARGET_UNVERIFIED', { deliveryId: parsed.deliveryId });
  }
  try {
    const reserved = await host.conclusionStore.reserveOnce({
      repositoryId: host.expectedRepositoryId,
      pullNumber: parsed.pullNumber, headSha: parsed.headSha,
      deliveryId: parsed.deliveryId,
    });
    if (reserved !== true) {
      return hold('CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED',
        { deliveryId: parsed.deliveryId });
    }
  } catch (_) {
    return hold('CONCLUSION_RESERVATION_UNVERIFIED',
      { deliveryId: parsed.deliveryId });
  }
  // A moved head after the reservation must not be published. The durable
  // tombstone remains, requiring independent reconciliation of that head.
  if (!(await freshCurrentTarget(parsed, host, token))) {
    return hold('PR_TARGET_CHANGED_AFTER_RESERVATION',
      { deliveryId: parsed.deliveryId });
  }
  return null;
}

async function processVerifiedGuardianTarget(parsed, host) {
  // Reject conflicting raw switches even if only one authorization grant is
  // present. Authorization must not silently resolve a mixed host setting.
  if (host.enableFullCheckWrites === true &&
      host.enableFailureCheckWrites === true) {
    return hold('FEATURE_OFF', { deliveryId: parsed.deliveryId });
  }
  const fullMode = host.enableFullCheckWrites === true &&
    host.founderAuthorizedFullMode === 'EXPLICIT_FULL_CHECK_WRITES';
  const failureOnlyMode = host.enableFailureCheckWrites === true &&
    host.founderAuthorizedFailureOnly === 'EXPLICIT_FAILURE_ONLY';
  // Mixed modes or partial configuration never silently select a mode.
  if ((fullMode && failureOnlyMode) ||
      (!fullMode && !failureOnlyMode)) {
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
      typeof host.githubAppPrivateKeyPem !== 'string' ||
      !host.conclusionStore ||
      typeof host.conclusionStore.reserveOnce !== 'function') {
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
      requireActionsRead: fullMode,
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
        requireConclusiveEvidence: fullMode,
        expectedGuardianAppId: host.guardianAppId,
      });
    } catch (_) { evidence = hold('GUARDIAN_EVIDENCE_READ_FAILED'); }
  }
  // A signed v1/v2 policy, missing review approval, unverified workflow
  // association, unbound branch rule or stale exact head can NEVER PASS.
  const reason = typeof evidence.reason === 'string' &&
    /^[A-Z0-9_]+$/.test(evidence.reason) ? evidence.reason : 'GUARDIAN_HOLD';
  const terminalFailure = fullMode &&
    reason === 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE';
  // Ordinary pre-review / pre-CI evidence is not a terminal failure. Keep the
  // required context missing (GitHub blocks merge) until an eligible later
  // event completes the same immutable head. No permanent conclusion row yet.
  if (fullMode && evidence.eligibleForSuccess !== true && !terminalFailure) {
    return hold('AWAITING_CONCLUSIVE_EXACT_HEAD_EVIDENCE', {
      evaluatedReason: reason, deliveryId: parsed.deliveryId,
    });
  }
  // G9: re-read App and repository installation authority after evaluating
  // evidence and immediately before the only supported Check Run write.
  // A stale persisted binding is never enough, and uncertainty is HOLD.
  try {
    await revalidateCurrentInstallationScope({
      appId: host.guardianAppId, installationId: parsed.installationId,
      privateKeyPem: host.githubAppPrivateKeyPem,
      installationToken: installationToken.token,
      expectedOwnerAccountId: host.expectedOwnerAccountId,
      expectedRepositoryId: host.expectedRepositoryId,
      requireActionsRead: fullMode,
    });
  } catch (_) {
    return hold('FRESH_INSTALLATION_SCOPE_UNVERIFIED', {
      deliveryId: parsed.deliveryId, evaluatedReason: reason,
    });
  }
  if (fullMode && evidence.eligibleForSuccess === true && policy) {
    const freshSignature = verifySignedPolicy(policy.envelope,
      policy.publicKeyPem, { requirePullBinding: true,
        expectedPullNumber: parsed.pullNumber });
    if (!freshSignature.signatureChecked ||
        freshSignature.headSha !== parsed.headSha ||
        !freshSignature.releasePolicy ||
        freshSignature.releasePolicy.guardianAppId !== host.guardianAppId ||
        freshSignature.payloadSha256 !== evidence.signedPolicySha256) {
      return hold('SIGNED_SUCCESS_AUTHORITY_STALE');
    }
    // Reservation follows policy and provenance checks, so ordinary pending
    // reviews do not permanently burn a head. Both modes share this gate.
    const conclusionHold = await reserveAndRecheckConclusion(parsed, host,
      installationToken.token);
    if (conclusionHold) return conclusionHold;
    try {
      const receipt = await postConclusiveSuccessCheck({
        token: installationToken.token, headSha: parsed.headSha,
        appId: host.guardianAppId,
        explicitFullModeGrant: 'GUARDIAN_HOST_EXPLICIT_FULL_MODE',
        summary: 'Independent signed policy, exact-head approval, GitHub Actions ' +
          'workflow job associations, required-check App bindings, and explicitly ' +
          'empty active ruleset bypass-actor lists verified at read time.',
      });
      return hold('SUCCESS_CHECK_RECORDED_RELEASE_HOLD', {
        deliveryId: parsed.deliveryId, checkRunId: receipt.checkRunId,
        conclusion: 'success', authoritativeRequiredCheck: 'ISSUED',
      });
    } catch (_) {
      return hold('SUCCESS_CHECK_NOT_CONFIRMED', { deliveryId: parsed.deliveryId });
    }
  }
  // Failure-only checks also occupy the SAME durable conclusion slot.
  // An unrelated delivery cannot overwrite a previous success/failure on an
  // unchanged head or produce conflicting completed Check Runs.
  const conclusionHold = await reserveAndRecheckConclusion(parsed, host,
    installationToken.token);
  if (conclusionHold) return conclusionHold;
  try {
    const receipt = await postFailureOnlyCheck({ token: installationToken.token,
      appId: host.guardianAppId,
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

module.exports = { verifyWebhook, processGuardianDelivery,
  processGuardianReconciliation };
