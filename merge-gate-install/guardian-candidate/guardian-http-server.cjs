/**
 * An unbound, non-listening Node HTTP handler for a future Guardian host.
 * Importing or calling createGuardianHttpServer does NOT start a server.
 * The owner-administered runtime must explicitly call server.listen() and
 * independently provision TLS termination, replay storage, keys and policy.
 */
'use strict';

const http = require('node:http');
const { processGuardianDelivery } = require('./guardian-webhook-runtime.cjs');
const { createGuardianOwnerHttpHandler } = require('./guardian-owner-http.cjs');

const MAX_BODY_BYTES = 256_000;

function sendJson(res, code, object) {
  if (res.headersSent) return;
  const response = JSON.stringify(object);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(response),
  });
  res.end(response);
}

function receiveBoundedBody(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (part) => {
      total += part.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('BODY_TOO_LARGE'));
        req.pause();
        return;
      }
      chunks.push(part);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('aborted', () => reject(new Error('BODY_ABORTED')));
    req.on('error', reject);
  });
}

function createGuardianHttpServer({ host }) {
  // `host` must be supplied by a separate protected runtime. Defaults OFF.
  // Owner onboarding is independently opt-in, requires protected host
  // dependencies, and does not enable webhook writes or launch authority.
  const ownerHandler = host?.enableOwnerOnboardingRoutes === true ?
    createGuardianOwnerHttpHandler({ host: host.ownerOnboarding }) : null;
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') {
      return sendJson(res, 200, { running: true,
        feature: 'OFF_OR_SOURCE_ONLY', releaseAuthority: 'NOT_ISSUED' });
    }
    if (ownerHandler) {
      try {
        if (await ownerHandler(req, res)) return;
      } catch (_) {
        return sendJson(res, 503, { status: 'INSTALLATION_HOLD',
          activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
      }
    }
    if (req.method !== 'POST' || req.url !== '/github/webhook') {
      return sendJson(res, 404, { error: 'NOT_FOUND' });
    }
    if (!/^application\/json(?:;|$)/i.test(String(req.headers['content-type'] || ''))) {
      return sendJson(res, 415, { error: 'UNSUPPORTED_MEDIA_TYPE' });
    }
    if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
      return sendJson(res, 413, { error: 'BODY_TOO_LARGE' });
    }
    let rawBody;
    try { rawBody = await receiveBoundedBody(req); } catch (_) {
      return sendJson(res, 413, { error: 'BODY_INVALID_OR_TOO_LARGE' });
    }
    let decision;
    try { decision = await processGuardianDelivery({
      rawBody, headers: req.headers, host,
    }); } catch (_) {
      decision = { status: 'SOURCE_ONLY_HOLD', reason: 'UNHANDLED_HOST_ERROR' };
    }
    // Do not echo webhook inputs, secrets, installation tokens or policy data.
    const checkRecorded = ['FAILURE_ONLY_CHECK_RECORDED',
      'SUCCESS_CHECK_RECORDED_RELEASE_HOLD'].includes(decision.reason);
    const acceptedHold = ['AWAITING_CONCLUSIVE_EXACT_HEAD_EVIDENCE',
      'DELIVERY_DUPLICATE_OR_NOT_RESERVED',
      'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED'].includes(decision.reason);
    const status = decision.reason === 'WEBHOOK_SIGNATURE_INVALID' ? 401 :
      decision.reason === 'WEBHOOK_TARGET_OUT_OF_SCOPE' ? 422 :
        (checkRecorded || acceptedHold) ? 202 : 503;
    return sendJson(res, status, {
      status: checkRecorded ? 'CHECK_RUN_RECORDED_RELEASE_HOLD' :
        acceptedHold ? 'ACCEPTED_NO_CHECK_RUN' : 'SOURCE_ONLY_HOLD',
      reason: decision.reason,
      activationAllowed: false,
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 1000;
  server.maxRequestsPerSocket = 10;
  return server;
}

module.exports = { createGuardianHttpServer };
