/**
 * GitHub App credential boundary (source-only, not configured or running).
 * The independent host supplies the App ID, installation ID and RSA key.
 * Never import credentials, installation identity, or permissions from a PR.
 */
'use strict';

const https = require('node:https');
const crypto = require('node:crypto');

const API_HOST = 'api.github.com';
const MAX_RESPONSE_BYTES = 128_000;
const SHA = /^[0-9a-f]{40}$/;

class GuardianApiError extends Error {
  constructor(code) { super(code); this.name = 'GuardianApiError'; this.code = code; }
}
function assert(condition, code) {
  if (!condition) throw new GuardianApiError(code);
}
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function encodeBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

/** Only hardcoded paths may be used. Redirects, proxies and arbitrary URLs are unsupported. */
function githubJson(method, path, authorization, body) {
  assert(['GET', 'POST'].includes(method) && typeof path === 'string' &&
    (path === '/repos/nohandsai01/test/check-runs' ||
      /^\/app\/installations\/[1-9]\d*\/access_tokens$/.test(path)),
  'GUARDIAN_GITHUB_PATH_FORBIDDEN');
  assert(typeof authorization === 'string' && authorization.length > 8 &&
    authorization.length < 5000 && /^[\x21-\x7e]+$/.test(authorization),
  'GUARDIAN_AUTHORIZATION_UNAVAILABLE');
  const payload = body === undefined ? undefined : JSON.stringify(body);
  assert(payload === undefined || Buffer.byteLength(payload) <= 16_384,
    'GUARDIAN_REQUEST_TOO_LARGE');
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: API_HOST, port: 443, protocol: 'https:', method, path,
      timeout: 10_000,
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'nohands-guardian-inert-host-candidate/1',
        Authorization: 'Bearer ' + authorization,
        ...(payload === undefined ? {} : {
          'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload),
        }),
      },
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
    }, (response) => {
      if (![200, 201].includes(response.statusCode)) {
        response.resume(); reject(new GuardianApiError('GUARDIAN_GITHUB_API_REJECTED')); return;
      }
      if (!/^application\/(?:json|vnd\.github\+json)(?:;|$)/i.test(
        String(response.headers['content-type'] || ''))) {
        response.resume(); reject(new GuardianApiError('GUARDIAN_GITHUB_CONTENT_TYPE')); return;
      }
      let bytes = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) {
          response.destroy(new GuardianApiError('GUARDIAN_GITHUB_RESPONSE_OVERSIZE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          assert(isRecord(result), 'GUARDIAN_GITHUB_JSON_INVALID');
          resolve(result);
        } catch (_) { reject(new GuardianApiError('GUARDIAN_GITHUB_JSON_INVALID')); }
      });
    });
    request.on('timeout', () => request.destroy(new GuardianApiError('GUARDIAN_GITHUB_TIMEOUT')));
    request.on('error', (error) => reject(error instanceof GuardianApiError ? error :
      new GuardianApiError('GUARDIAN_GITHUB_TRANSPORT')));
    request.end(payload);
  });
}

function createAppJwt({ appId, privateKeyPem, now = Date.now() }) {
  assert(Number.isSafeInteger(appId) && appId > 0 && typeof privateKeyPem === 'string' &&
    privateKeyPem.length > 100 && privateKeyPem.length < 20_000 &&
    Number.isFinite(now), 'GUARDIAN_APP_IDENTITY_INVALID');
  const iat = Math.floor(now / 1000) - 60;
  const claims = { iat, exp: iat + 540, iss: String(appId) };
  const encoded = encodeBase64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' +
    encodeBase64Url(JSON.stringify(claims));
  try {
    const key = crypto.createPrivateKey(privateKeyPem);
    assert(key.asymmetricKeyType === 'rsa', 'GUARDIAN_APP_KEY_NOT_RSA');
    return encoded + '.' + crypto.sign('RSA-SHA256', Buffer.from(encoded), key).toString('base64url');
  } catch (_) { throw new GuardianApiError('GUARDIAN_APP_KEY_INVALID'); }
}

/** Token never leaves the trusted host except as an Authorization header. */
async function mintScopedInstallationToken({ appId, installationId, privateKeyPem }) {
  assert(Number.isSafeInteger(installationId) && installationId > 0,
    'GUARDIAN_INSTALLATION_ID_INVALID');
  const jwt = createAppJwt({ appId, privateKeyPem });
  // Explicit repository and least-privilege permission intersection.
  const response = await githubJson('POST', '/app/installations/' + installationId +
    '/access_tokens', jwt, {
    repositories: ['test'],
    permissions: { checks: 'write', pull_requests: 'read' },
  });
  assert(typeof response.token === 'string' && response.token.length >= 16 &&
    typeof response.expires_at === 'string' &&
    Date.parse(response.expires_at) > Date.now() + 60_000 &&
    isRecord(response.permissions) && response.permissions.checks === 'write' &&
    response.permissions.pull_requests === 'read' &&
    Array.isArray(response.repositories) && response.repositories.length === 1 &&
    isRecord(response.repositories[0]) &&
    response.repositories[0].full_name === 'nohandsai01/test' &&
    response.repository_selection === 'selected',
  'GUARDIAN_SCOPED_TOKEN_UNVERIFIED');
  return { token: response.token, expiresAt: response.expires_at,
    installationId, appId };
}

/** Deliberately no generic check writer or success conclusion is exposed. */
async function postFailureOnlyCheck({ token, headSha, summary }) {
  assert(typeof headSha === 'string' && SHA.test(headSha) &&
    typeof summary === 'string' && summary.length <= 3000 &&
    summary.length > 0 && /^[\x20-\x7e\n]+$/.test(summary),
  'GUARDIAN_FAILURE_CHECK_INVALID');
  const result = await githubJson('POST', '/repos/nohandsai01/test/check-runs', token, {
    name: 'NO HANDS Merge Gate Required Check', head_sha: headSha,
    status: 'completed', conclusion: 'failure',
    output: { title: 'Guardian HOLD — release not authorized', summary },
  });
  assert(Number.isSafeInteger(result.id) && result.id > 0 &&
    result.name === 'NO HANDS Merge Gate Required Check' &&
    result.head_sha === headSha && result.conclusion === 'failure',
  'GUARDIAN_FAILURE_CHECK_RECEIPT_INVALID');
  return { checkRunId: result.id, headSha, conclusion: 'failure' };
}

module.exports = { createAppJwt, mintScopedInstallationToken,
  postFailureOnlyCheck, GuardianApiError };
