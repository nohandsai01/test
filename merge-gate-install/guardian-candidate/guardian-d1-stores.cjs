/**
 * Durable, source-only Cloudflare D1 adapters. No database is created, opened,
 * migrated or queried by importing this module. The owner-run host must supply
 * an isolated D1 binding with the companion schema applied.
 *
 * D1 changes=1 under a database uniqueness constraint is the only accepted
 * successful reservation. Uncertain writes always fail closed.
 */
'use strict';

const crypto = require('node:crypto');

const DELIVERY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const PKCE = /^[A-Za-z0-9_-]{43}$/;

class GuardianStoreError extends Error {
  constructor(code) { super(code); this.name = 'GuardianStoreError'; this.code = code; }
}
function assert(ok, code) {
  if (!ok) throw new GuardianStoreError(code);
}
function positiveInteger(n) { return Number.isSafeInteger(n) && n > 0; }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function isoUtc(value) {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function d1(db) {
  assert(db && typeof db.prepare === 'function', 'GUARDIAN_D1_BINDING_UNAVAILABLE');
  return db;
}
async function run(db, sql, params) {
  try {
    const statement = d1(db).prepare(sql);
    assert(statement && typeof statement.bind === 'function',
      'GUARDIAN_D1_PREPARE_INVALID');
    const result = await statement.bind(...params).run();
    assert(result && result.success === true && result.meta &&
      Number.isSafeInteger(result.meta.changes) &&
      result.meta.changes >= 0 && result.meta.changes <= 1,
    'GUARDIAN_D1_RESULT_UNVERIFIED');
    return result.meta.changes;
  } catch (e) {
    if (e instanceof GuardianStoreError) throw e;
    throw new GuardianStoreError('GUARDIAN_D1_WRITE_FAILED');
  }
}
async function first(db, sql, params) {
  try {
    const statement = d1(db).prepare(sql);
    assert(statement && typeof statement.bind === 'function',
      'GUARDIAN_D1_PREPARE_INVALID');
    const result = await statement.bind(...params).first();
    assert(result === null || (result && typeof result === 'object' &&
      !Array.isArray(result)), 'GUARDIAN_D1_READ_INVALID');
    return result;
  } catch (e) {
    if (e instanceof GuardianStoreError) throw e;
    throw new GuardianStoreError('GUARDIAN_D1_READ_FAILED');
  }
}

function createGuardianD1Stores(db) {
  d1(db);
  return Object.freeze({
    oauthStore: Object.freeze({
      async putIfAbsent({ stateSha256, browserSessionId,
        installationStateSha256, installationId, setupAction,
        codeVerifier, expiresAt }) {
        assert(HASH.test(stateSha256) && HASH.test(installationStateSha256) &&
          typeof browserSessionId === 'string' &&
          /^[A-Za-z0-9_-]{16,256}$/.test(browserSessionId) &&
          positiveInteger(installationId) &&
          ['install', 'update'].includes(setupAction) &&
          PKCE.test(codeVerifier) && isoUtc(expiresAt) &&
          Date.parse(expiresAt) > Date.now() &&
          Date.parse(expiresAt) <= Date.now() + 11 * 60_000,
        'GUARDIAN_OAUTH_STATE_INVALID');
        return (await run(db,
          'INSERT OR IGNORE INTO guardian_owner_oauth_states ' +
          '(state_hash, browser_session_hash, installation_state_hash, ' +
          'installation_id, setup_action, code_verifier, expires_at) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?)',
          [stateSha256, sha256(browserSessionId), installationStateSha256,
            installationId, setupAction, codeVerifier, expiresAt])) === 1;
      },
      async takeOnce({ stateSha256, browserSessionId,
        installationStateSha256, now }) {
        assert(HASH.test(stateSha256) && HASH.test(installationStateSha256) &&
          typeof browserSessionId === 'string' &&
          /^[A-Za-z0-9_-]{16,256}$/.test(browserSessionId) && isoUtc(now),
        'GUARDIAN_OAUTH_STATE_INVALID');
        const ownerHash = sha256(browserSessionId);
        // UPDATE is the atomic replay gate. A subsequent read is deliberately
        // made only after changes=1; any read uncertainty fails closed.
        const changed = await run(db,
          'UPDATE guardian_owner_oauth_states SET consumed_at = ? ' +
          'WHERE state_hash = ? AND browser_session_hash = ? AND ' +
          'installation_state_hash = ? AND consumed_at IS NULL AND expires_at > ?',
          [now, stateSha256, ownerHash, installationStateSha256, now]);
        if (changed !== 1) return null;
        const row = await first(db,
          'SELECT installation_id, setup_action, code_verifier ' +
          'FROM guardian_owner_oauth_states WHERE state_hash = ? ' +
          'AND browser_session_hash = ? AND installation_state_hash = ? ' +
          'AND consumed_at = ?',
          [stateSha256, ownerHash, installationStateSha256, now]);
        assert(row && positiveInteger(row.installation_id) &&
          ['install', 'update'].includes(row.setup_action) &&
          PKCE.test(row.code_verifier), 'GUARDIAN_OAUTH_CONSUMED_ROW_INVALID');
        return Object.freeze({ installationId: row.installation_id,
          setupAction: row.setup_action, codeVerifier: row.code_verifier });
      },
    }),
    intentStore: Object.freeze({
      async putIfAbsent({ stateSha256, ownerSessionId, expiresAt }) {
        assert(HASH.test(stateSha256) && typeof ownerSessionId === 'string' &&
          ownerSessionId.length >= 16 && ownerSessionId.length <= 256 &&
          isoUtc(expiresAt) && Date.parse(expiresAt) > Date.now() &&
          Date.parse(expiresAt) <= Date.now() + 11 * 60_000,
        'GUARDIAN_INSTALL_INTENT_INVALID');
        return (await run(db,
          'INSERT OR IGNORE INTO guardian_install_intents ' +
          '(state_hash, owner_session_hash, expires_at) VALUES (?, ?, ?)',
          [stateSha256, sha256(ownerSessionId), expiresAt])) === 1;
      },
      async consumeIfOwnerAndUnexpired({ stateSha256, ownerSessionId, now }) {
        assert(HASH.test(stateSha256) && typeof ownerSessionId === 'string' &&
          ownerSessionId.length >= 16 && ownerSessionId.length <= 256 &&
          isoUtc(now), 'GUARDIAN_INSTALL_INTENT_INVALID');
        // Atomic UPDATE prevents two concurrent callback workers from both
        // consuming the same state. Never deletes an intent for retry.
        return (await run(db,
          'UPDATE guardian_install_intents SET consumed_at = ? ' +
          'WHERE state_hash = ? AND owner_session_hash = ? ' +
          'AND consumed_at IS NULL AND expires_at > ?',
          [now, stateSha256, sha256(ownerSessionId), now])) === 1;
      },
    }),
    installationStore: Object.freeze({
      async bindVerifiedOnce({ installationId, appId, ownerAccountId,
        repositoryId, verifiedAt }) {
        assert(positiveInteger(installationId) && positiveInteger(appId) &&
          positiveInteger(ownerAccountId) && positiveInteger(repositoryId) &&
          isoUtc(verifiedAt), 'GUARDIAN_INSTALLATION_BINDING_INVALID');
        return (await run(db,
          'INSERT OR IGNORE INTO guardian_installation_bindings ' +
          '(installation_id, app_id, owner_account_id, repository_id, verified_at) ' +
          'VALUES (?, ?, ?, ?, ?)',
          [installationId, appId, ownerAccountId, repositoryId, verifiedAt])) === 1;
      },
      async getVerifiedBinding(installationId) {
        assert(positiveInteger(installationId), 'GUARDIAN_INSTALLATION_ID_INVALID');
        const row = await first(db,
          'SELECT installation_id, app_id, owner_account_id, repository_id, verified_at ' +
          'FROM guardian_installation_bindings WHERE installation_id = ?',
          [installationId]);
        if (row === null) return null;
        assert(positiveInteger(row.installation_id) && positiveInteger(row.app_id) &&
          positiveInteger(row.owner_account_id) && positiveInteger(row.repository_id) &&
          isoUtc(row.verified_at), 'GUARDIAN_INSTALLATION_RECORD_INVALID');
        return Object.freeze({
          installationId: row.installation_id, appId: row.app_id,
          ownerAccountId: row.owner_account_id, repositoryId: row.repository_id,
          verifiedAt: row.verified_at,
        });
      },
    }),
    deliveryStore: Object.freeze({
      async reserveOnce(deliveryId, { installationId, pullNumber, headSha }) {
        assert(DELIVERY.test(deliveryId) && positiveInteger(installationId) &&
          positiveInteger(pullNumber) && SHA.test(headSha),
        'GUARDIAN_DELIVERY_RESERVATION_INVALID');
        // Permanent tombstones by default: no TTL deletion that could
        // inadvertently re-enable an old GitHub delivery ID. An INSERT result
        // is not enough to authorize subsequent API calls: read back the exact
        // committed record, and treat missing/ambiguous reads as HOLD.
        const deliveryHash = sha256(deliveryId.toLowerCase());
        const changed = await run(db,
          'INSERT OR IGNORE INTO guardian_delivery_receipts ' +
          '(delivery_hash, installation_id, pull_number, head_sha) ' +
          'VALUES (?, ?, ?, ?)',
          [deliveryHash, installationId, pullNumber, headSha]);
        if (changed !== 1) return false;
        const row = await first(db,
          'SELECT delivery_hash, installation_id, pull_number, head_sha ' +
          'FROM guardian_delivery_receipts WHERE delivery_hash = ?',
          [deliveryHash]);
        assert(row && row.delivery_hash === deliveryHash &&
          row.installation_id === installationId &&
          row.pull_number === pullNumber && row.head_sha === headSha,
        'GUARDIAN_DELIVERY_RESERVATION_READBACK_INVALID');
        return true;
      },
    }),
    conclusionStore: Object.freeze({
      async reserveOnce({ repositoryId, pullNumber, headSha, deliveryId }) {
        assert(positiveInteger(repositoryId) && positiveInteger(pullNumber) &&
          SHA.test(headSha) && DELIVERY.test(deliveryId),
        'GUARDIAN_CONCLUSION_RESERVATION_INVALID');
        const deliveryHash = sha256(deliveryId.toLowerCase());
        const changed = await run(db,
          'INSERT OR IGNORE INTO guardian_conclusion_reservations ' +
          '(repository_id, pull_number, head_sha, delivery_hash) ' +
          'VALUES (?, ?, ?, ?)',
          [repositoryId, pullNumber, headSha, deliveryHash]);
        if (changed !== 1) return false;
        // Bind the SQL primary key and the delivery tombstone to the same
        // event. Do not infer a successful, durable once-per-head reservation
        // from a write acknowledgment that lacks its matching committed row.
        const row = await first(db,
          'SELECT repository_id, pull_number, head_sha, delivery_hash ' +
          'FROM guardian_conclusion_reservations WHERE repository_id = ? ' +
          'AND pull_number = ? AND head_sha = ?',
          [repositoryId, pullNumber, headSha]);
        assert(row && row.repository_id === repositoryId &&
          row.pull_number === pullNumber && row.head_sha === headSha &&
          row.delivery_hash === deliveryHash,
        'GUARDIAN_CONCLUSION_RESERVATION_READBACK_INVALID');
        return true;
      },
      async getReservation({ repositoryId, pullNumber, headSha }) {
        assert(positiveInteger(repositoryId) && positiveInteger(pullNumber) &&
          SHA.test(headSha), 'GUARDIAN_CONCLUSION_LOOKUP_INVALID');
        // Operator-facing read only. The reservation can never be deleted,
        // reset, or reused to grant another Check publication attempt.
        const row = await first(db,
          'SELECT repository_id, pull_number, head_sha, delivery_hash, created_at ' +
          'FROM guardian_conclusion_reservations WHERE repository_id = ? ' +
          'AND pull_number = ? AND head_sha = ?',
          [repositoryId, pullNumber, headSha]);
        if (row === null) return null;
        assert(row.repository_id === repositoryId &&
          row.pull_number === pullNumber && row.head_sha === headSha &&
          typeof row.delivery_hash === 'string' && HASH.test(row.delivery_hash) &&
          isoUtc(row.created_at),
        'GUARDIAN_CONCLUSION_LOOKUP_ROW_INVALID');
        return Object.freeze({
          repositoryId, pullNumber, headSha,
          deliveryHash: row.delivery_hash, createdAt: row.created_at,
        });
      },
    }),
  });
}

module.exports = { createGuardianD1Stores, GuardianStoreError };
