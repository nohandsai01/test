/**
 * Protected, read-only HTTP operator route for investigating uncertain
 * Guardian Check publications. No listener, credentials, or GitHub writes.
 * The separately administered host owns authentication, CSRF, rate limiting
 * and repository-scoped, checks:read token issuance.
 */
'use strict';

const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');
const { reconcileGuardianConclusionBatch, MAX_BATCH_TARGETS } =
  require('./guardian-conclusion-batch.cjs');

const ROUTE = '/guardian/operator/check-reconcile';
const MAX_BODY_BYTES = 4096;
const SHA = /^[a-f0-9]{40}$/;
const SESSION = /^[A-Za-z0-9_-]{16,256}$/;

function validOrigin(raw) {
  if (typeof raw !== 'string' || raw.length > 256) return false;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' && url.origin === raw &&
      url.username === '' && url.password === '' && url.search === '' &&
      url.hash === '' && (url.port === '' || url.port === '443');
  } catch (_) { return false; }
}
function integer(n) { return Number.isSafeInteger(n) && n > 0; }
function record(n) { return n !== null && typeof n === 'object' && !Array.isArray(n); }
function ownShape(o, fields) {
  return record(o) && Object.keys(o).length === fields.length &&
    fields.every((field) => Object.hasOwn(o, field));
}
function boundedTargets(value) {
  if (!Array.isArray(value) || value.length < 1 ||
      value.length > MAX_BATCH_TARGETS) return null;
  const observed = new Set(), targets = [];
  for (const row of value) {
    if (!ownShape(row, ['pullNumber', 'headSha']) ||
        !integer(row.pullNumber) || typeof row.headSha !== 'string' ||
        !SHA.test(row.headSha)) return null;
    const key = row.pullNumber + ':' + row.headSha;
    if (observed.has(key)) return null;
    observed.add(key);
    targets.push(Object.freeze({ pullNumber: row.pullNumber,
      headSha: row.headSha }));
  }
  return Object.freeze(targets);
}
function reply(res, status, reason, entries) {
  if (res.headersSent || res.writableEnded || res.destroyed) return;
  // All responses are hard HOLDs and always exclude raw input / credentials.
  const body = { status: 'SOURCE_ONLY_HOLD', reason,
    trusted: false, activationAllowed: false,
    authoritativeRequiredCheck: 'NOT_ISSUED',
    automaticRetryAllowed: false, releaseAuthorized: false };
  if (entries) body.observations = entries;
  const bytes = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': bytes.length,
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Referrer-Policy': 'no-referrer',
  });
  res.end(bytes);
}
function readBody(req, declared) {
  return new Promise((resolve, reject) => {
    let bytes = 0, completed = false;
    const pieces = [];
    req.on('data', (part) => {
      if (!Buffer.isBuffer(part)) return reject(new Error('INVALID_BODY_PART'));
      bytes += part.length;
      if (bytes > MAX_BODY_BYTES || bytes > declared) {
        req.pause();
        return reject(new Error('BODY_TOO_LARGE'));
      }
      pieces.push(part);
    });
    req.on('aborted', () => reject(new Error('INCOMPLETE_BODY')));
    req.on('error', () => reject(new Error('BODY_STREAM_FAILED')));
    req.on('close', () => {
      if (!completed) reject(new Error('INCOMPLETE_BODY'));
    });
    req.on('end', () => {
      completed = true;
      if (bytes !== declared) return reject(new Error('BAD_CONTENT_LENGTH'));
      resolve(Buffer.concat(pieces));
    });
  });
}

function createGuardianOperatorHttpHandler({ host }) {
  // Fail immediately instead of accidentally exposing a partially configured
  // route. No credentials may originate in the request or PR.
  if (!record(host) || !validOrigin(host.publicOrigin) ||
      !integer(host.ownerAccountId) || !integer(host.repositoryId) ||
      !integer(host.guardianAppId) ||
      typeof host.authenticateOwnerRequest !== 'function' ||
      typeof host.verifyCsrf !== 'function' ||
      typeof host.issueReadOnlyToken !== 'function' ||
      !host.rateLimiter || typeof host.rateLimiter.allow !== 'function' ||
      !host.conclusionStore ||
      typeof host.conclusionStore.getReservation !== 'function') {
    throw new Error('GUARDIAN_OPERATOR_TRUST_CONFIGURATION_MISSING');
  }
  const expectedHost = new URL(host.publicOrigin).host;
  return async function handleGuardianOperatorHttp(req, res) {
    if (req.url !== ROUTE && req.url !== ROUTE + '?') return false;
    const invalid = (status, reason) => { reply(res, status, reason); return true; };
    if (req.method !== 'POST' || req.url !== ROUTE ||
        req.headers.host !== expectedHost ||
        (req.headers['x-forwarded-host'] !== undefined &&
          req.headers['x-forwarded-host'] !== expectedHost) ||
        req.headers['transfer-encoding'] !== undefined ||
        req.headers['content-encoding'] !== undefined ||
        req.headers['content-type'] !== 'application/json' ||
        req.headers.origin !== host.publicOrigin ||
        typeof req.headers['x-guardian-csrf'] !== 'string' ||
        req.headers['x-guardian-csrf'].length < 16 ||
        req.headers['x-guardian-csrf'].length > 256) {
      return invalid(403, 'GUARDIAN_OPERATOR_REQUEST_REJECTED');
    }
    const rawLength = req.headers['content-length'];
    if (typeof rawLength !== 'string' ||
        !/^[1-9][0-9]*$/.test(rawLength) ||
        !Number.isSafeInteger(Number(rawLength)) ||
        Number(rawLength) > MAX_BODY_BYTES) {
      return invalid(413, 'GUARDIAN_OPERATOR_BODY_BOUND_INVALID');
    }
    let session;
    try { session = await host.authenticateOwnerRequest(req); }
    catch (_) { return invalid(401, 'GUARDIAN_OPERATOR_AUTH_UNVERIFIED'); }
    if (!record(session) || !SESSION.test(session.sessionId) ||
        session.ownerAccountId !== host.ownerAccountId) {
      return invalid(401, 'GUARDIAN_OPERATOR_AUTH_UNVERIFIED');
    }
    try {
      if (await host.verifyCsrf({
        sessionId: session.sessionId, token: req.headers['x-guardian-csrf'],
      }) !== true) return invalid(403, 'GUARDIAN_OPERATOR_CSRF_REJECTED');
      if (await host.rateLimiter.allow({
        sessionId: session.sessionId, phase: 'CHECK_RECONCILIATION_READ',
      }) !== true) return invalid(429, 'GUARDIAN_OPERATOR_RATE_LIMITED');
    } catch (_) { return invalid(503, 'GUARDIAN_OPERATOR_AUTHORITY_UNAVAILABLE'); }

    let payload;
    try { payload = parseUniqueKeySourceLock(
      await readBody(req, Number(rawLength))); }
    catch (_) { return invalid(400, 'GUARDIAN_OPERATOR_JSON_OR_BODY_INVALID'); }
    if (!ownShape(payload, ['schemaVersion', 'targets']) ||
        payload.schemaVersion !== 1) {
      return invalid(400, 'GUARDIAN_OPERATOR_TARGET_SET_INVALID');
    }
    const targets = boundedTargets(payload.targets);
    if (!targets) return invalid(400, 'GUARDIAN_OPERATOR_TARGET_SET_INVALID');

    let token;
    try { token = await host.issueReadOnlyToken({
      sessionId: session.sessionId, repositoryId: host.repositoryId,
      expectedAppId: host.guardianAppId,
    }); } catch (_) { return invalid(503, 'GUARDIAN_OPERATOR_TOKEN_UNVERIFIED'); }
    if (!record(token) || token.repositoryId !== host.repositoryId ||
        token.appId !== host.guardianAppId ||
        typeof token.value !== 'string' || token.value.length < 16 ||
        token.value.length > 4096 || !/^[\x21-\x7e]+$/.test(token.value) ||
        !ownShape(token.permissions, ['checks', 'pull_requests', 'metadata']) ||
        token.permissions.checks !== 'read' ||
        token.permissions.pull_requests !== 'read' ||
        token.permissions.metadata !== 'read') {
      return invalid(503, 'GUARDIAN_OPERATOR_TOKEN_UNVERIFIED');
    }

    let report;
    try {
      report = await reconcileGuardianConclusionBatch({
        repositoryId: host.repositoryId, expectedAppId: host.guardianAppId,
        installationToken: token.value,
        conclusionStore: host.conclusionStore,
        targets,
      });
    } catch (_) { return invalid(503, 'GUARDIAN_OPERATOR_READ_FAILED'); }
    if (!record(report) || report.status !== 'SOURCE_ONLY_HOLD' ||
        report.trusted !== false || report.activationAllowed !== false ||
        report.releaseAuthorized !== false ||
        report.automaticRetryAllowed !== false ||
        report.authoritativeRequiredCheck !== 'NOT_ISSUED' ||
        report.evaluatedTargetCount !== targets.length ||
        !Array.isArray(report.entries) || report.entries.length !== targets.length) {
      return invalid(503, 'GUARDIAN_OPERATOR_RESULT_UNVERIFIED');
    }
    // The batch has already removed secrets and restricted output metadata.
    return reply(res, 200, 'GUARDIAN_OPERATOR_OBSERVATIONS_ONLY', report.entries);
  };
}

module.exports = { createGuardianOperatorHttpHandler, ROUTE };
