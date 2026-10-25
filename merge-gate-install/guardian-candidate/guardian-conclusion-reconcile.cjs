/**
 * Read-only operator reconciliation after an uncertain Guardian Check POST.
 *
 * An observed Check is NEVER a merge approval, release permission, or a
 * reason to delete a D1 reservation. A missing Check is NEVER retry authority.
 * Host must provide a protected, repository-scoped read token and D1 store.
 * Importing this module performs no I/O.
 */
'use strict';

const { collectAuthenticatedGithubSnapshot } =
  require('./github-rest-collector.cjs');

const REPO = 'nohandsai01/test';
const NAME = 'NO HANDS Merge Gate Required Check';
const SHA = /^[0-9a-f]{40}$/;

function integer(n) { return Number.isSafeInteger(n) && n > 0; }
function hold(reason, additional = {}) {
  return Object.freeze({
    schemaVersion: 1,
    status: 'SOURCE_ONLY_HOLD',
    reason,
    trusted: false, activationAllowed: false,
    authoritativeRequiredCheck: 'NOT_ISSUED',
    automaticRetryAllowed: false,
    releaseAuthorized: false,
    ...additional,
  });
}

/**
 * Read-only result suitable for operator triage, never for an issuer.
 * getReservation must be provided by the verified protected D1 adapter,
 * not from candidate PR input. No path to reserveOnce/postCheck exists here.
 */
async function reconcileGuardianConclusion({ repositoryId, pullNumber, headSha,
  expectedAppId, installationToken, conclusionStore } = {}) {
  if (!integer(repositoryId) || !integer(pullNumber) || !SHA.test(headSha || '') ||
      !integer(expectedAppId) || typeof installationToken !== 'string' ||
      installationToken.length < 16 || installationToken.length > 4096 ||
      !/^[\x21-\x7e]+$/.test(installationToken) ||
      !conclusionStore || typeof conclusionStore.getReservation !== 'function') {
    return hold('RECONCILIATION_INPUT_OR_OWNER_AUTHORITY_INVALID');
  }

  let reservation;
  try {
    reservation = await conclusionStore.getReservation({
      repositoryId, pullNumber, headSha,
    });
  } catch (_) {
    return hold('RECONCILIATION_DURABLE_READ_UNVERIFIED');
  }
  if (reservation === null) {
    // The absence of an immutable reservation cannot authorize a Check POST.
    return hold('RECONCILIATION_NO_RESERVATION', { remoteReadPerformed: false });
  }
  if (!reservation || reservation.repositoryId !== repositoryId ||
      reservation.pullNumber !== pullNumber || reservation.headSha !== headSha ||
      typeof reservation.deliveryHash !== 'string' ||
      !/^[0-9a-f]{64}$/.test(reservation.deliveryHash) ||
      typeof reservation.createdAt !== 'string' ||
      !Number.isFinite(Date.parse(reservation.createdAt))) {
    return hold('RECONCILIATION_RESERVATION_INVALID');
  }

  let snapshot;
  try {
    snapshot = await collectAuthenticatedGithubSnapshot({
      pullNumber, expectedHeadSha: headSha, installationToken,
    });
  } catch (_) {
    return hold('RECONCILIATION_GITHUB_EVIDENCE_UNAVAILABLE', {
      reservationObserved: true,
    });
  }
  if (!snapshot || snapshot.repository !== REPO ||
      snapshot.pullRequest?.number !== pullNumber ||
      snapshot.pullRequest?.head?.sha !== headSha ||
      snapshot.pullRequest?.base?.ref !== 'main' ||
      snapshot.pullRequest?.head?.repo?.full_name !== REPO ||
      snapshot.pullRequest?.base?.repo?.full_name !== REPO ||
      !Array.isArray(snapshot.checkRuns?.check_runs) ||
      !Number.isSafeInteger(snapshot.checkRuns.total_count) ||
      snapshot.checkRuns.total_count !== snapshot.checkRuns.check_runs.length) {
    return hold('RECONCILIATION_SNAPSHOT_INVALID', {
      reservationObserved: true,
    });
  }

  const sameName = snapshot.checkRuns.check_runs.filter((item) =>
    item && item.name === NAME);
  const common = { reservationObserved: true, observedHeadSha: headSha,
    observedMatchingNameCount: sameName.length };
  if (!sameName.length) {
    // A failure before/during POST and a delayed GitHub Check are
    // observationally indistinguishable. Neither permits automatic retry.
    return hold('RECONCILIATION_NO_CHECK_OBSERVED_NOT_SAFE_TO_RETRY', common);
  }
  if (sameName.length !== 1) {
    return hold('RECONCILIATION_AMBIGUOUS_CHECKS', common);
  }
  const check = sameName[0];
  if (!integer(check.id) || check.head_sha !== headSha ||
      check.app?.id !== expectedAppId) {
    return hold('RECONCILIATION_CHECK_ISSUER_OR_SHA_UNVERIFIED', common);
  }
  if (check.status !== 'completed' ||
      !['success', 'failure'].includes(check.conclusion) ||
      typeof check.completed_at !== 'string' ||
      !Number.isFinite(Date.parse(check.completed_at))) {
    return hold('RECONCILIATION_CHECK_NOT_CONCLUSIVE', common);
  }
  if (Date.parse(check.completed_at) < Date.parse(reservation.createdAt)) {
    return hold('RECONCILIATION_CHECK_PREDATES_RESERVATION', common);
  }
  return hold('RECONCILIATION_CHECK_OBSERVED_ONLY', {
    ...common, observedCheckRunId: check.id,
    observedConclusion: check.conclusion,
    observedCompletedAt: check.completed_at,
  });
}

module.exports = { reconcileGuardianConclusion };
