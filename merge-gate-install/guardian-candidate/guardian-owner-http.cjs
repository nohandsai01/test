/**
 * Inert owner-onboarding HTTP adapter for Guardian's GitHub App.
 *
 * No listener, GitHub App registration, cookie session authority or migration
 * is created by importing this module. A separately authenticated owner host
 * must inject session verification, CSRF verification and durable rate limits.
 */
'use strict';

const { beginGuardianInstallation } = require('./github-app-onboarding.cjs');
const { beginGuardianSetupOAuth, completeGuardianSetupOAuth } =
  require('./guardian-owner-oauth.cjs');

const START = '/guardian/install/start';
const SETUP = '/guardian/install/setup';
const CALLBACK = '/guardian/install/oauth/callback';
const COOKIE = '__Host-guardian_install_state';
const STATE = /^[A-Za-z0-9_-]{43}$/;
const SESSION = /^[A-Za-z0-9_-]{16,256}$/;
const DECIMAL_ID = /^[1-9][0-9]{0,15}$/;
const MAX_URL_BYTES = 2048;
const MAX_COOKIE_BYTES = 4096;

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function publicOriginValid(value) {
  if (typeof value !== 'string' || value.length > 256) return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.origin === value &&
      !u.username && !u.password && !u.hash && !u.search &&
      (u.port === '' || u.port === '443');
  } catch (_) { return false; }
}
function exactQuery(req, publicOrigin, path, keys) {
  if (typeof req.url !== 'string' ||
      Buffer.byteLength(req.url) > MAX_URL_BYTES || req.url.includes('#')) return null;
  let url;
  try { url = new URL(req.url, publicOrigin); } catch (_) { return null; }
  if (url.origin !== publicOrigin || url.pathname !== path ||
      url.searchParams.size !== keys.length) return null;
  const actual = [...url.searchParams.keys()];
  if (actual.length !== new Set(actual).size ||
      actual.some((key) => !keys.includes(key)) ||
      keys.some((key) => !url.searchParams.has(key))) return null;
  return url.searchParams;
}
function installationCookie(req) {
  const raw = req.headers.cookie;
  if (typeof raw !== 'string' || raw.length > MAX_COOKIE_BYTES) return null;
  let found = null;
  for (const part of raw.split(';')) {
    const item = part.trim();
    const eq = item.indexOf('=');
    if (eq < 0) continue;
    if (item.slice(0, eq) !== COOKIE) continue;
    if (found !== null) return null; // Ambiguous cookies fail closed.
    found = item.slice(eq + 1);
  }
  return STATE.test(found || '') ? found : null;
}
function cookieHeader(state) {
  const value = STATE.test(state || '') ? state : '';
  return `${COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${value ? 600 : 0}`;
}
function reply(res, status, body, cookie) {
  if (res.headersSent || res.writableEnded) return;
  const bytes = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': bytes.length,
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...(cookie === undefined ? {} : { 'Set-Cookie': cookieHeader(cookie) }),
  });
  res.end(bytes);
}
function redirect(res, location, status, state) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(status, {
    Location: location,
    'Content-Length': '0',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...(state === undefined ? {} : { 'Set-Cookie': cookieHeader(state) }),
  });
  res.end();
}
function isPinnedGitHubRedirect(location, expectedPath) {
  if (typeof location !== 'string' || location.length > 2048) return false;
  try {
    const url = new URL(location);
    return url.protocol === 'https:' && url.hostname === 'github.com' &&
      url.port === '' && !url.username && !url.password && !url.hash &&
      url.pathname === expectedPath;
  } catch (_) { return false; }
}

/**
 * `authenticateOwnerRequest` must return an independently authenticated,
 * server-owned { sessionId, ownerAccountId }. It must never infer identity
 * from query parameters, supplied cookies alone, or GitHub redirect claims.
 */
function createGuardianOwnerHttpHandler({ host }) {
  const origin = host?.publicOrigin;
  if (!publicOriginValid(origin) || !record(host) ||
      typeof host.authenticateOwnerRequest !== 'function' ||
      typeof host.verifyCsrf !== 'function' ||
      !host.rateLimiter || typeof host.rateLimiter.allow !== 'function' ||
      !host.intentStore || !host.oauthStore || !host.installationStore ||
      typeof host.appSlug !== 'string' || !/^[a-z0-9][a-z0-9-]{1,98}$/.test(host.appSlug) ||
      !Number.isSafeInteger(host.appId) || host.appId <= 0 ||
      !Number.isSafeInteger(host.expectedOwnerAccountId) || host.expectedOwnerAccountId <= 0 ||
      host.redirectUri !== origin + CALLBACK ||
      typeof host.clientId !== 'string' || typeof host.clientSecret !== 'string' ||
      typeof host.privateKeyPem !== 'string') {
    throw new Error('GUARDIAN_OWNER_HOST_TRUST_CONFIG_MISSING');
  }
  const expectedHost = new URL(origin).host;
  return async function handleGuardianOwnerHttp(req, res) {
    let path;
    try { path = new URL(req.url, origin).pathname; } catch (_) { return false; }
    if (![START, SETUP, CALLBACK].includes(path)) return false;
    const fail = (status = 503, clearCookie = false) => {
      reply(res, status, { status: 'INSTALLATION_HOLD', activated: false,
        releaseAuthority: 'NOT_ISSUED' }, clearCookie ? '' : undefined);
      return true;
    };
    // The external TLS terminator must pin this Host; untrusted forwarding
    // headers are intentionally ignored by this router.
    if (req.headers.host !== expectedHost ||
        req.headers['x-forwarded-host'] && req.headers['x-forwarded-host'] !== expectedHost ||
        req.headers['transfer-encoding'] ||
        (path === START && (req.method !== 'POST' || req.headers['content-length'] !== '0')) ||
        (path !== START && req.method !== 'GET')) return fail(404);

    let session;
    try { session = await host.authenticateOwnerRequest(req); } catch (_) { return fail(401); }
    if (!record(session) || !SESSION.test(session.sessionId || '') ||
        session.ownerAccountId !== host.expectedOwnerAccountId) return fail(401);
    try {
      if (await host.rateLimiter.allow({ phase: path, sessionId: session.sessionId }) !== true) {
        return fail(429);
      }
    } catch (_) { return fail(503); }

    if (path === START) {
      if (req.headers.origin !== origin ||
          typeof req.headers['x-guardian-csrf'] !== 'string') return fail(403);
      try {
        if (await host.verifyCsrf({ sessionId: session.sessionId,
          token: req.headers['x-guardian-csrf'] }) !== true) return fail(403);
      } catch (_) { return fail(403); }
      if (exactQuery(req, origin, START, []) === null) return fail(400);
      let result;
      try { result = await beginGuardianInstallation({
        appSlug: host.appSlug, verifiedOwnerSessionId: session.sessionId,
        intentStore: host.intentStore,
      }); } catch (_) { return fail(); }
      if (result?.status !== 'INSTALLATION_LINK_ISSUED_NOT_AUTHORIZED' ||
          !STATE.test(result.stateForHostCookie || '') ||
          !isPinnedGitHubRedirect(result.url,
            `/apps/${host.appSlug}/installations/new`)) return fail();
      redirect(res, result.url, 303, result.stateForHostCookie);
      return true;
    }

    const originalState = installationCookie(req);
    if (!originalState) return fail(403, true);
    if (path === SETUP) {
      // GitHub documents installation_id; setup_action is not guaranteed in
      // every setup redirect. A missing action is only a local intent label,
      // never installation verification or authorization.
      const query = exactQuery(req, origin, SETUP,
        ['installation_id', 'setup_action']) ||
        exactQuery(req, origin, SETUP, ['installation_id']);
      if (!query) return fail(400, true);
      const rawId = query.get('installation_id');
      const installationId = DECIMAL_ID.test(rawId || '') ? Number(rawId) : NaN;
      if (!Number.isSafeInteger(installationId)) return fail(400, true);
      let result;
      try { result = await beginGuardianSetupOAuth({
        installationState: originalState, installationId,
        setupAction: query.get('setup_action') || 'install',
        browserSessionId: session.sessionId,
        clientId: host.clientId, redirectUri: host.redirectUri,
        oauthStore: host.oauthStore,
      }); } catch (_) { return fail(); }
      if (result?.status !== 'OAUTH_REDIRECT_ISSUED_NOT_AUTHORIZED' ||
          !isPinnedGitHubRedirect(result.url, '/login/oauth/authorize')) return fail();
      redirect(res, result.url, 302);
      return true;
    }

    const query = exactQuery(req, origin, CALLBACK, ['code', 'state']);
    if (!query) return fail(400, true);
    let outcome;
    try { outcome = await completeGuardianSetupOAuth({
      state: query.get('state'), code: query.get('code'),
      installationState: originalState, browserSessionId: session.sessionId,
      oauthStore: host.oauthStore, intentStore: host.intentStore,
      installationStore: host.installationStore,
      clientId: host.clientId, clientSecret: host.clientSecret,
      redirectUri: host.redirectUri, appId: host.appId,
      privateKeyPem: host.privateKeyPem,
      expectedOwnerAccountId: host.expectedOwnerAccountId,
    }); } catch (_) { return fail(503, true); }
    if (outcome?.status !== 'INSTALLATION_VERIFIED_NOT_ACTIVATED' ||
        outcome.accountVerified !== true || outcome.installed !== true ||
        outcome.activated !== false) return fail(503, true);
    reply(res, 200, { status: 'INSTALLATION_VERIFIED_NOT_ACTIVATED',
      activated: false, releaseAuthority: 'NOT_ISSUED' }, '');
    return true;
  };
}

module.exports = { createGuardianOwnerHttpHandler };
