/**
 * Source-only GitHub App web OAuth -> setup-intent bridge.
 *
 * There are TWO redirects: installation -> Setup URL, then authorization ->
 * OAuth Callback URL. GitHub does not vouch for the installation_id supplied
 * to Setup URL. This bridge carries it only in a one-time server-side D1
 * record and verifies it against GitHub's API after OAuth.
 *
 * Importing this file does not start a listener, authenticate a user, store
 * a token, install an App, or authorize any Guardian feature.
 */
'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const { consumeGuardianSetupIntent } = require('./github-app-onboarding.cjs');

const STATE = /^[A-Za-z0-9_-]{43}$/;
const CODE = /^[A-Za-z0-9_-]{12,512}$/;
const CLIENT_ID = /^[A-Za-z0-9_.-]{8,128}$/;
const MAX_TOKEN_RESPONSE_BYTES = 8_192;

function hold(reason) {
  return Object.freeze({ status: 'INSTALLATION_HOLD', reason,
    accountVerified: false, installed: false, activated: false });
}
function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function sessionIdValid(value) {
  return typeof value === 'string' && value.length >= 16 &&
    value.length <= 256 && /^[A-Za-z0-9_-]+$/.test(value);
}
function callbackValid(value) {
  if (typeof value !== 'string' || value.length > 1024) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !!url.hostname && !url.username &&
      !url.password && !url.hash && !url.search &&
      (url.port === '' || url.port === '443');
  } catch (_) { return false; }
}

/**
 * Called by the trusted owner host from the GitHub App *setup* callback.
 * `installationState` comes from the protected host cookie created by
 * beginGuardianInstallation; it must NOT be read from GitHub's query string.
 * `browserSessionId` comes from a protected session, never an HTTP parameter.
 */
async function beginGuardianSetupOAuth({ installationState, installationId,
  setupAction, browserSessionId, clientId, redirectUri, oauthStore }) {
  if (!STATE.test(installationState || '') ||
      !Number.isSafeInteger(installationId) || installationId <= 0 ||
      !['install', 'update'].includes(setupAction) ||
      !sessionIdValid(browserSessionId) || !CLIENT_ID.test(clientId || '') ||
      !callbackValid(redirectUri) || !oauthStore ||
      typeof oauthStore.putIfAbsent !== 'function') {
    return hold('OAUTH_SETUP_INPUT_OR_SESSION_INVALID');
  }
  const state = crypto.randomBytes(32).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  try {
    const reserved = await oauthStore.putIfAbsent({
      stateSha256: digest(state), browserSessionId,
      installationStateSha256: digest(installationState),
      installationId, setupAction, codeVerifier: verifier,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    if (reserved !== true) return hold('OAUTH_STATE_NOT_PERSISTED');
  } catch (_) { return hold('OAUTH_STATE_STORE_FAILURE'); }

  const query = new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri,
    state, code_challenge: crypto.createHash('sha256').update(verifier)
      .digest('base64url'), code_challenge_method: 'S256',
    allow_signup: 'false',
  });
  return Object.freeze({
    status: 'OAUTH_REDIRECT_ISSUED_NOT_AUTHORIZED',
    url: 'https://github.com/login/oauth/authorize?' + query.toString(),
    accountVerified: false, installed: false, activated: false,
  });
}

/** Strict, fixed-origin authorization-code exchange; credentials are never logged. */
function exchangeGitHubAppCode({ code, codeVerifier, clientId,
  clientSecret, redirectUri }) {
  if (!CODE.test(code || '') || !STATE.test(codeVerifier || '') ||
      !CLIENT_ID.test(clientId || '') ||
      typeof clientSecret !== 'string' || clientSecret.length < 12 ||
      clientSecret.length > 512 || !callbackValid(redirectUri)) {
    return Promise.reject(new Error('OAUTH_EXCHANGE_INPUT_INVALID'));
  }
  const body = new URLSearchParams({
    client_id: clientId, client_secret: clientSecret, code,
    redirect_uri: redirectUri, code_verifier: codeVerifier,
  }).toString();
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: 'github.com', port: 443, protocol: 'https:',
      path: '/login/oauth/access_token', method: 'POST', timeout: 8_000,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store',
        'User-Agent': 'nohands-guardian-inert-oauth-bridge/1',
      },
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
    }, (response) => {
      // Never follow redirects, including on the token exchange endpoint.
      if (response.statusCode !== 200 ||
          !/^application\/json(?:;|$)/i.test(String(
            response.headers['content-type'] || ''))) {
        response.resume(); reject(new Error('OAUTH_EXCHANGE_REJECTED')); return;
      }
      let total = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_TOKEN_RESPONSE_BYTES) {
          response.destroy(new Error('OAUTH_RESPONSE_OVERSIZE')); return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('aborted', () => reject(new Error('OAUTH_RESPONSE_ABORTED')));
      response.on('end', () => {
        try {
          const token = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!token || typeof token !== 'object' || Array.isArray(token) ||
              typeof token.access_token !== 'string' ||
              !/^ghu_[A-Za-z0-9_]{12,4090}$/.test(token.access_token) ||
              String(token.token_type).toLowerCase() !== 'bearer' ||
              Object.hasOwn(token, 'error')) {
            reject(new Error('OAUTH_TOKEN_NOT_VERIFIED')); return;
          }
          // Intentionally discard refresh_token and all non-access-token data.
          resolve(token.access_token);
        } catch (_) { reject(new Error('OAUTH_RESPONSE_INVALID')); }
      });
    });
    request.on('timeout', () => request.destroy(new Error('OAUTH_EXCHANGE_TIMEOUT')));
    request.on('error', () => reject(new Error('OAUTH_EXCHANGE_TRANSPORT')));
    request.end(body);
  });
}

/**
 * Called by the protected GitHub App OAuth callback. One-time D1 consumption
 * happens BEFORE the token exchange. The authorized token is used only for a
 * direct `/user` + installation cross-check inside the existing onboarding
 * function and never leaves this invocation or reaches persistent storage.
 */
async function completeGuardianSetupOAuth({ state, code, installationState,
  browserSessionId, oauthStore, intentStore, installationStore,
  clientId, clientSecret, redirectUri, appId, privateKeyPem,
  expectedOwnerAccountId }) {
  if (!STATE.test(state || '') || !CODE.test(code || '') ||
      !STATE.test(installationState || '') ||
      !sessionIdValid(browserSessionId) || !oauthStore ||
      typeof oauthStore.takeOnce !== 'function' ||
      !Number.isSafeInteger(expectedOwnerAccountId) ||
      expectedOwnerAccountId <= 0) {
    return hold('OAUTH_CALLBACK_INPUT_OR_SESSION_INVALID');
  }
  let pending;
  try {
    pending = await oauthStore.takeOnce({
      stateSha256: digest(state), browserSessionId,
      installationStateSha256: digest(installationState),
      now: new Date().toISOString(),
    });
  } catch (_) { return hold('OAUTH_STATE_STORE_FAILURE'); }
  if (!pending || !STATE.test(pending.codeVerifier || '') ||
      !Number.isSafeInteger(pending.installationId) ||
      pending.installationId <= 0 ||
      !['install', 'update'].includes(pending.setupAction)) {
    return hold('OAUTH_STATE_MISMATCH_EXPIRED_OR_REPLAYED');
  }
  let ownerUserAccessToken;
  try {
    ownerUserAccessToken = await exchangeGitHubAppCode({
      code, codeVerifier: pending.codeVerifier, clientId, clientSecret,
      redirectUri,
    });
  } catch (_) { return hold('OAUTH_CODE_EXCHANGE_FAILED'); }

  // No account identity is trusted from the browser, installation redirect,
  // or token response alone. The on-chain check is GitHub's authenticated
  // `/user`, App installation and selected repository API responses.
  return consumeGuardianSetupIntent({
    state: installationState, installationId: pending.installationId,
    setupAction: pending.setupAction, verifiedOwnerSessionId: browserSessionId,
    intentStore, installationStore, appId, privateKeyPem,
    ownerUserAccessToken, expectedOwnerAccountId,
  });
}

module.exports = { beginGuardianSetupOAuth, completeGuardianSetupOAuth };
