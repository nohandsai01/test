/**
 * Operator-side bounded multi-PR investigation of uncertain Check writes.
 * SOURCE ONLY. Every verdict is HOLD. Importing this module has no I/O.
 * Reuses the protected D1 reservation and authenticated GitHub snapshot reads
 * from guardian-conclusion-reconcile; no Check writes, retries or unlocks.
 */
'use strict';

const { reconcileGuardianConclusion } = require('./guardian-conclusion-reconcile.cjs');

const SHA = /^[0-9a-f]{40}$/;
const REASON = /^RECONCILIATION_[A-Z0-9_]+$/;
const MAX_BATCH_TARGETS = 8;
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function freezeBatch(reason, entries) {
  const counts = {};
  for (const item of entries) {
    counts[item.reason] = (counts[item.reason] ?? 0) + 1;
  }
  return Object.freeze({
    schemaVersion: 1,
    status: 'SOURCE_ONLY_HOLD',
    reason,
    trusted: false,
    activationAllowed: false,
    authoritativeRequiredCheck: 'NOT_ISSUED',
    automaticRetryAllowed: false,
    releaseAuthorized: false,
    evaluatedTargetCount: entries.length,
    maximumTargetCount: MAX_BATCH_TARGETS,
    countsByReason: Object.freeze(counts),
    entries: Object.freeze(entries),
  });
}
function invalid() {
  // Never echo tokens, delivery IDs, opaque store responses or caller data.
  return freezeBatch('RECONCILIATION_BATCH_INPUT_INVALID', []);
}
function snapshotTargets(targets) {
  if (!Array.isArray(targets) || targets.length < 1 ||
      targets.length > MAX_BATCH_TARGETS) return null;
  const keys = new Set(), pinned = [];
  for (const target of targets) {
    if (!target || typeof target !== 'object' || Array.isArray(target)) return null;
    // Read each property exactly once, before the first asynchronous read.
    // Caller mutation while D1/GitHub requests are pending cannot change
    // the identity in a later report item.
    const pullNumber = target.pullNumber, headSha = target.headSha;
    if (!positive(pullNumber) || typeof headSha !== 'string' ||
        !SHA.test(headSha)) return null;
    const key = `${pullNumber}:${headSha}`;
    if (keys.has(key)) return null;
    keys.add(key);
    pinned.push(Object.freeze({ pullNumber, headSha }));
  }
  return Object.freeze(pinned);
}
function safeEntry(target, evidence) {
  if (!evidence || evidence.status !== 'SOURCE_ONLY_HOLD' ||
      evidence.trusted !== false || evidence.activationAllowed !== false ||
      evidence.automaticRetryAllowed !== false ||
      evidence.releaseAuthorized !== false ||
      evidence.authoritativeRequiredCheck !== 'NOT_ISSUED' ||
      typeof evidence.reason !== 'string' || !REASON.test(evidence.reason)) {
    return Object.freeze({
      pullNumber: target.pullNumber, headSha: target.headSha,
      status: 'SOURCE_ONLY_HOLD', reason: 'RECONCILIATION_BATCH_ENTRY_UNVERIFIED',
    });
  }
  // Fixed allowlist of public, non-authorizing metadata only. Never spread
  // untrusted remote fields or return installation tokens/delivery digests.
  const entry = {
    pullNumber: target.pullNumber,
    headSha: target.headSha,
    status: 'SOURCE_ONLY_HOLD',
    reason: evidence.reason,
  };
  if (typeof evidence.reservationObserved === 'boolean') {
    entry.reservationObserved = evidence.reservationObserved;
  }
  if (typeof evidence.remoteReadPerformed === 'boolean') {
    entry.remoteReadPerformed = evidence.remoteReadPerformed;
  }
  if (Number.isSafeInteger(evidence.observedMatchingNameCount) &&
      evidence.observedMatchingNameCount >= 0 &&
      evidence.observedMatchingNameCount <= 1000) {
    entry.observedMatchingNameCount = evidence.observedMatchingNameCount;
  }
  if (positive(evidence.observedCheckRunId)) {
    entry.observedCheckRunId = evidence.observedCheckRunId;
  }
  if (['success', 'failure'].includes(evidence.observedConclusion)) {
    entry.observedConclusion = evidence.observedConclusion;
  }
  return Object.freeze(entry);
}

async function reconcileGuardianConclusionBatch({ repositoryId, targets,
  expectedAppId, installationToken, conclusionStore } = {}) {
  let pinnedTargets;
  try {
    if (!positive(repositoryId) || !positive(expectedAppId) ||
        typeof installationToken !== 'string' ||
        installationToken.length < 16 || installationToken.length > 4096 ||
        !/^[\x21-\x7e]+$/.test(installationToken) ||
        !conclusionStore || typeof conclusionStore.getReservation !== 'function' ||
        !(pinnedTargets = snapshotTargets(targets))) return invalid();
  } catch (_) {
    // Proxies and throwing getters never reach D1 or GitHub.
    return invalid();
  }

  const entries = [];
  // Serial order is deliberate: bound API reads (<=8), no burst, and each
  // independently fails closed. A bad target does not authorize retries or
  // mask other targets' observations. No bounded batch ever returns ALLOW.
  for (const target of pinnedTargets) {
    let evidence;
    try {
      evidence = await reconcileGuardianConclusion({
        repositoryId, pullNumber: target.pullNumber, headSha: target.headSha,
        expectedAppId, installationToken, conclusionStore,
      });
    } catch (_) {
      evidence = { status: 'SOURCE_ONLY_HOLD', reason: 'RECONCILIATION_BATCH_ENTRY_UNVERIFIED',
        trusted: false, activationAllowed: false, automaticRetryAllowed: false,
        releaseAuthorized: false, authoritativeRequiredCheck: 'NOT_ISSUED' };
    }
    entries.push(safeEntry(target, evidence));
  }
  return freezeBatch('RECONCILIATION_BATCH_OBSERVATIONS_ONLY', entries);
}

module.exports = { reconcileGuardianConclusionBatch, MAX_BATCH_TARGETS };
