/**
 * Bounded source-only integration: independent signed policy -> authenticated
 * GitHub App installation REST reads -> exact-head evidence shape inspection.
 * No check is created and no positive authorization is ever returned.
 */
'use strict';

const { verifySignedPolicy } = require('./signed-policy.cjs');
const { collectAuthenticatedGithubSnapshot, CollectorError } =
  require('./github-rest-collector.cjs');
const { inspectEvidenceSnapshot } = require('./evidence-snapshot.cjs');
const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');
const { collectGuardianConclusiveProvenance, GuardianProvenanceError } =
  require('./guardian-provenance.cjs');

function hold(reason, details = {}) {
  return {
    schemaVersion: 1,
    status: 'SOURCE_ONLY_HOLD',
    reason,
    trusted: false,
    activationAllowed: false,
    authoritativeRequiredCheck: 'NOT_ISSUED',
    hostedCheckEvidence: 'NOT_VERIFIED',
    unresolvedAuthority: [
      'RUNTIME_TRUST_ANCHOR_PROVENANCE_NOT_ATTESTED',
      'GITHUB_APP_HOST_NOT_INSTALLED_OR_VERIFIED',
      'LAST_PUSH_AND_REVIEW_PROVENANCE_NOT_VERIFIED',
      'BRANCH_RULESET_NOT_VERIFIED',
    ],
    ...details,
  };
}

/**
 * Runtime inputs MUST be injected outside the candidate branch by an
 * independently administered Guardian host. No environment variable is read
 * automatically: callers cannot silently fall back to a PR author token/key.
 */
async function readAndEvaluateGuardianCandidate(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return hold('GUARDIAN_RUNTIME_INPUT_INVALID');
  }
  const {
    pullNumber, signedPolicyEnvelope, trustedPolicyPublicKeyPem,
    githubAppInstallationToken, requireConclusiveEvidence = false,
    expectedGuardianAppId,
  } = input;
  const verification = verifySignedPolicy(signedPolicyEnvelope,
    trustedPolicyPublicKeyPem, {
      requirePullBinding: true, expectedPullNumber: pullNumber,
    });
  if (!verification.signatureChecked) {
    return hold(verification.reason || 'EXTERNAL_POLICY_NOT_VERIFIED');
  }

  let snapshot;
  try {
    snapshot = await collectAuthenticatedGithubSnapshot({
      pullNumber,
      expectedHeadSha: verification.headSha,
      installationToken: githubAppInstallationToken,
    });
  } catch (error) {
    return hold(error instanceof CollectorError ? error.code : 'GITHUB_READ_FAILED', {
      signedPolicySha256: verification.payloadSha256,
    });
  }
  const shape = inspectEvidenceSnapshot(verification.rawPolicy,
    Buffer.from(JSON.stringify(snapshot), 'utf8'));
  if (requireConclusiveEvidence === true) {
    if (shape.findings.length) return hold('GITHUB_EVIDENCE_REJECTED', {
      evidenceFindings: shape.findings, signedPolicySha256: verification.payloadSha256,
    });
    if (!verification.releasePolicy ||
        verification.releasePolicy.guardianAppId !== expectedGuardianAppId) {
      return hold('SIGNED_CONCLUSIVE_POLICY_MISSING_OR_APP_MISMATCH');
    }
    let provenance;
    try {
      const expectedEvidence = parseUniqueKeySourceLock(verification.rawPolicy).evidence;
      provenance = await collectGuardianConclusiveProvenance({
        pullNumber, headSha: verification.headSha,
        installationToken: githubAppInstallationToken, snapshot,
        expectedEvidence, releasePolicy: verification.releasePolicy,
        guardianAppId: expectedGuardianAppId,
      });
      // Exact-head second read ensures a changing PR/check page cannot be
      // silently promoted after review/workflow/ruleset evidence is collected.
      const reread = await collectAuthenticatedGithubSnapshot({
        pullNumber, expectedHeadSha: verification.headSha,
        installationToken: githubAppInstallationToken,
      });
      if (JSON.stringify(reread) !== JSON.stringify(snapshot)) {
        return hold('GUARDIAN_SNAPSHOT_CHANGED_BEFORE_CHECK_WRITE');
      }
    } catch (error) {
      return hold(error instanceof GuardianProvenanceError ? error.code :
        error instanceof CollectorError ? error.code :
          'GUARDIAN_PROVENANCE_UNVERIFIED');
    }
    return hold('EVIDENCE_CONCLUSIVE_CANDIDATE', {
      eligibleForSuccess: true, // Not an activation permission by itself.
      signedPolicySha256: verification.payloadSha256,
      observedHeadSha: verification.headSha,
      provenance,
    });
  }
  return hold(shape.findings.length ? 'GITHUB_EVIDENCE_REJECTED' :
    'EVIDENCE_SHAPE_MATCH_ONLY', {
    signedPolicySha256: verification.payloadSha256,
    evidenceFindings: shape.findings,
    evidenceShapeStatus: shape.status,
    observedHeadSha: verification.headSha,
    observedCheckRunCount: snapshot.checkRuns.total_count,
  });
}

module.exports = { readAndEvaluateGuardianCandidate };
