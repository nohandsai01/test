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
        // inadvertently re-enable an old GitHub delivery ID.
        return (await run(db,
          'INSERT OR IGNORE INTO guardian_delivery_receipts ' +
          '(delivery_hash, installation_id, pull_number, head_sha) ' +
          'VALUES (?, ?, ?, ?)',
          [sha256(deliveryId.toLowerCase()), installationId, pullNumber, headSha])) === 1;
      },
    }),
  });
}

module.exports = { createGuardianD1Stores, GuardianStoreError };
