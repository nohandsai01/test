/**
 * Verify an off-repository Ed25519 policy signature. The caller MUST obtain
 * trustedPublicKeyPem from an independently managed runtime trust store, never
 * from a pull request, repository file, webhook body, or policy envelope.
 * This is a signature primitive, not a hosted Guardian authority grant.
 */
'use strict';

const crypto = require('node:crypto');
const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');

const SHA = /^[0-9a-f]{40}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 60 * 1000;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const REQUIRED_CHECK = 'NO HANDS Merge Gate Required Check';

function plain(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    Object.getPrototypeOf(x) === Object.prototype;
}
function fields(x, wanted) {
  return plain(x) && Object.keys(x).sort().join('\0') === [...wanted].sort().join('\0');
}
function decodeBase64(x, maxBytes) {
  if (typeof x !== 'string' || !x.length || x.length > 350_000 || !B64.test(x)) {
    throw new Error('Invalid base64.');
  }
  const value = Buffer.from(x, 'base64');
  if (!value.length || value.length > maxBytes || value.toString('base64') !== x) {
    throw new Error('Noncanonical base64.');
  }
  return value;
}
function rejected(reason) {
  return {
    status: 'EXTERNAL_POLICY_REJECTED', reason, signatureChecked: false,
    trusted: false, activationAllowed: false,
  };
}

function verifySignedPolicy(rawEnvelope, trustedPublicKeyPem, scope = {}) {
  try {
    const requirePullBinding = scope && scope.requirePullBinding === true;
    if (requirePullBinding && (!Number.isSafeInteger(scope.expectedPullNumber) ||
        scope.expectedPullNumber <= 0)) {
      return rejected('SIGNED_POLICY_EXPECTED_PULL_INVALID');
    }
    if ((!Buffer.isBuffer(rawEnvelope) && typeof rawEnvelope !== 'string') ||
        typeof trustedPublicKeyPem !== 'string' || trustedPublicKeyPem.length > 10_000) {
      return rejected('POLICY_TRUST_ANCHOR_UNAVAILABLE');
    }
    const envelope = parseUniqueKeySourceLock(rawEnvelope);
    if (!fields(envelope, ['schemaVersion', 'algorithm', 'payloadBase64', 'signatureBase64']) ||
        envelope.schemaVersion !== 1 || envelope.algorithm !== 'Ed25519') {
      return rejected('POLICY_ENVELOPE_INVALID');
    }
    const payloadBytes = decodeBase64(envelope.payloadBase64, 128_000);
    const signature = decodeBase64(envelope.signatureBase64, 64);
    if (signature.length !== 64) return rejected('POLICY_SIGNATURE_INVALID');
    const publicKey = crypto.createPublicKey(trustedPublicKeyPem);
    if (publicKey.asymmetricKeyType !== 'ed25519' ||
        !crypto.verify(null, payloadBytes, publicKey, signature)) {
      return rejected('POLICY_SIGNATURE_INVALID');
    }

    const signed = parseUniqueKeySourceLock(payloadBytes);
    const scopedV2 = fields(signed, ['schemaVersion', 'issuedAt', 'expiresAt',
      'pullNumber', 'evidencePolicy']) && signed.schemaVersion === 2 &&
      Number.isSafeInteger(signed.pullNumber) && signed.pullNumber > 0;
    const scopedV3 = fields(signed, ['schemaVersion', 'issuedAt', 'expiresAt',
      'pullNumber', 'evidencePolicy', 'releasePolicy']) && signed.schemaVersion === 3 &&
      Number.isSafeInteger(signed.pullNumber) && signed.pullNumber > 0;
    const legacyV1 = fields(signed,
      ['schemaVersion', 'issuedAt', 'expiresAt', 'evidencePolicy']) &&
      signed.schemaVersion === 1;
    if ((!scopedV2 && !scopedV3 && !legacyV1) ||
        (requirePullBinding && (!(scopedV2 || scopedV3) ||
          signed.pullNumber !== scope.expectedPullNumber)) ||
        !fields(signed.evidencePolicy,
          ['schemaVersion', 'repository', 'targetBranch', 'headSha', 'evidence'])) {
      return rejected(requirePullBinding ? 'SIGNED_POLICY_PULL_NUMBER_UNBOUND' :
        'SIGNED_POLICY_FIELDS_INVALID');
    }
    const policy = signed.evidencePolicy;
    if (policy.schemaVersion !== 1 || policy.repository !== 'nohandsai01/test' ||
        policy.targetBranch !== 'main' || !SHA.test(policy.headSha)) {
      return rejected('SIGNED_POLICY_SCOPE_INVALID');
    }
    if (!Array.isArray(policy.evidence) || policy.evidence.length !== 2) {
      return rejected('SIGNED_POLICY_EVIDENCE_INVALID');
    }
    const types = new Set();
    const names = new Set();
    for (const item of policy.evidence) {
      if (!fields(item, ['type', 'checkName', 'issuerAppId']) ||
          !['tests', 'ci'].includes(item.type) || types.has(item.type) ||
          typeof item.checkName !== 'string' || !item.checkName.length ||
          item.checkName.length > 120 || /[\x00-\x1f]/.test(item.checkName) ||
          item.checkName === REQUIRED_CHECK || names.has(item.checkName) ||
          !Number.isSafeInteger(item.issuerAppId) || item.issuerAppId <= 0) {
        return rejected('SIGNED_POLICY_EVIDENCE_INVALID');
      }
      types.add(item.type);
      names.add(item.checkName);
    }
    // Only the new signed v3 contract can authorize a *candidate* for a
    // positive Check Run. A legacy v1/v2 signature never upgrades silently.
    if (scopedV3) {
      const release = signed.releasePolicy;
      if (!fields(release, ['schemaVersion', 'guardianAppId', 'reviewerIds',
        'minApprovals', 'workflows']) || release.schemaVersion !== 1 ||
        !Number.isSafeInteger(release.guardianAppId) || release.guardianAppId <= 0 ||
        !Array.isArray(release.reviewerIds) || release.reviewerIds.length < 1 ||
        release.reviewerIds.length > 8 ||
        new Set(release.reviewerIds).size !== release.reviewerIds.length ||
        release.reviewerIds.some((id) => !Number.isSafeInteger(id) || id <= 0) ||
        !Number.isSafeInteger(release.minApprovals) || release.minApprovals < 1 ||
        release.minApprovals > release.reviewerIds.length ||
        !Array.isArray(release.workflows) || release.workflows.length !== 2) {
        return rejected('SIGNED_RELEASE_POLICY_INVALID');
      }
      const boundTypes = new Set();
      if (policy.evidence.some((item) => item.issuerAppId === release.guardianAppId)) {
        return rejected('SIGNED_RELEASE_GUARDIAN_SELF_EVIDENCE');
      }
      for (const binding of release.workflows) {
        if (!fields(binding, ['type', 'workflowId', 'event']) ||
            !types.has(binding.type) || boundTypes.has(binding.type) ||
            !Number.isSafeInteger(binding.workflowId) || binding.workflowId <= 0 ||
            !['pull_request', 'push'].includes(binding.event)) {
          return rejected('SIGNED_RELEASE_WORKFLOW_INVALID');
        }
        boundTypes.add(binding.type);
      }
    }
    const issued = Date.parse(signed.issuedAt);
    const expires = Date.parse(signed.expiresAt);
    const now = Date.now();
    if (typeof signed.issuedAt !== 'string' || typeof signed.expiresAt !== 'string' ||
        !UTC_TIMESTAMP.test(signed.issuedAt) || !UTC_TIMESTAMP.test(signed.expiresAt) ||
        !Number.isFinite(issued) || !Number.isFinite(expires) ||
        expires <= issued || expires - issued > MAX_LIFETIME_MS ||
        issued > now + CLOCK_SKEW_MS || expires <= now) {
      return rejected('SIGNED_POLICY_EXPIRED_OR_INVALID');
    }
    return {
      status: 'EXTERNAL_SIGNATURE_VALID_ONLY',
      signatureChecked: true,
      payloadSha256: crypto.createHash('sha256').update(payloadBytes).digest('hex'),
      rawPolicy: Buffer.from(JSON.stringify(policy), 'utf8'),
      headSha: policy.headSha,
      pullNumber: scopedV2 || scopedV3 ? signed.pullNumber : null,
      releasePolicy: scopedV3 ? JSON.parse(JSON.stringify(signed.releasePolicy)) : null,
      trusted: false, activationAllowed: false,
    };
  } catch (_) {
    return rejected('POLICY_BYTES_OR_KEY_INVALID');
  }
}

module.exports = { verifySignedPolicy };
