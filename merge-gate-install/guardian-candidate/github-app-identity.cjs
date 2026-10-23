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
  const permitted = (method === 'POST' &&
    (path === '/repos/nohandsai01/test/check-runs' ||
      /^\/app\/installations\/[1-9]\d*\/access_tokens$/.test(path))) ||
    (method === 'GET' &&
      (path === '/user' || path === '/repos/nohandsai01/test' ||
        path === '/repos/nohandsai01/test/installation' ||
        /^\/app\/installations\/[1-9]\d*$/.test(path)));
  assert(permitted && typeof path === 'string',
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

/**
 * Validate a claimed setup installation against GitHub identities, not the
 * untrusted redirect parameters. The user token MUST be bound to the same
 * protected owner session by the external OAuth host before calling.
 */
async function verifyOwnerInstallationBinding({ appId, installationId,
  privateKeyPem, ownerUserAccessToken, expectedOwnerAccountId }) {
  assert(Number.isSafeInteger(installationId) && installationId > 0 &&
    Number.isSafeInteger(expectedOwnerAccountId) && expectedOwnerAccountId > 0 &&
    typeof ownerUserAccessToken === 'string' &&
    ownerUserAccessToken.length >= 16 && ownerUserAccessToken.length <= 4096,
  'GUARDIAN_BINDING_INPUT_INVALID');
  const jwt = createAppJwt({ appId, privateKeyPem });
  // Each endpoint is pinned and authenticated. A redirect is NOT followed.
  const user = await githubJson('GET', '/user', ownerUserAccessToken);
  const installation = await githubJson('GET',
    '/app/installations/' + installationId, jwt);
  const repoInstallation = await githubJson('GET',
    '/repos/nohandsai01/test/installation', jwt);
  const repository = await githubJson('GET',
    '/repos/nohandsai01/test', ownerUserAccessToken);
  const owner = (entry) => isRecord(entry) && isRecord(entry.account) &&
    entry.account.id === expectedOwnerAccountId &&
    entry.account.login === 'nohandsai01' &&
    entry.target_id === expectedOwnerAccountId &&
    entry.target_type === 'User';
  assert(user.id === expectedOwnerAccountId &&
    user.login === 'nohandsai01' && user.type === 'User' &&
    installation.id === installationId &&
    installation.app_id === appId && owner(installation) &&
    installation.repository_selection === 'selected' &&
    installation.suspended_at === null &&
    isRecord(installation.permissions) &&
    installation.permissions.checks === 'write' &&
    installation.permissions.pull_requests === 'read' &&
    Array.isArray(installation.events) &&
    installation.events.includes('pull_request') &&
    repoInstallation.id === installationId &&
    repoInstallation.app_id === appId && owner(repoInstallation) &&
    repoInstallation.repository_selection === 'selected' &&
    repoInstallation.suspended_at === null &&
    isRecord(repository.owner) &&
    repository.full_name === 'nohandsai01/test' &&
    repository.owner.id === expectedOwnerAccountId &&
    repository.owner.login === 'nohandsai01' &&
    Number.isSafeInteger(repository.id) && repository.id > 0,
  'GUARDIAN_INSTALLATION_OWNER_OR_REPO_UNVERIFIED');
  return Object.freeze({
    installationId, appId, ownerAccountId: expectedOwnerAccountId,
    repositoryId: repository.id,
    repository: 'nohandsai01/test',
    verifiedAt: new Date().toISOString(),
    activated: false,
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
async function mintScopedInstallationToken({ appId, installationId, privateKeyPem,
  expectedRepositoryId }) {
  assert(Number.isSafeInteger(installationId) && installationId > 0,
    'GUARDIAN_INSTALLATION_ID_INVALID');
  assert(Number.isSafeInteger(expectedRepositoryId) && expectedRepositoryId > 0,
    'GUARDIAN_REPOSITORY_ID_UNVERIFIED');
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
    response.repositories[0].id === expectedRepositoryId &&
    response.repository_selection === 'selected',
  'GUARDIAN_SCOPED_TOKEN_UNVERIFIED');
  return { token: response.token, expiresAt: response.expires_at,
    installationId, appId };
}

/**
 * G9: fresh GitHub App/installation/repository identity immediately before
 * any future FAILURE-only Check Run write. Old D1 bindings alone are not
 * current authorization. All calls use fixed GitHub HTTPS paths, not PR input.
 * A successful read is a point-in-time observation, not an atomic lease.
 */
async function revalidateCurrentInstallationScope({ appId, installationId,
  privateKeyPem, installationToken, expectedOwnerAccountId,
  expectedRepositoryId }) {
  assert(Number.isSafeInteger(installationId) && installationId > 0 &&
    Number.isSafeInteger(expectedOwnerAccountId) && expectedOwnerAccountId > 0 &&
    Number.isSafeInteger(expectedRepositoryId) && expectedRepositoryId > 0,
  'GUARDIAN_FRESH_SCOPE_INPUT_INVALID');
  const jwt = createAppJwt({ appId, privateKeyPem });
  // A 404, suspension, changed owner, removed repository, reduced
  // permission, unexpected installation or transport uncertainty HOLDS.
  const [installation, repositoryInstallation, repository] = await Promise.all([
    githubJson('GET', '/app/installations/' + installationId, jwt),
    githubJson('GET', '/repos/nohandsai01/test/installation', jwt),
    githubJson('GET', '/repos/nohandsai01/test', installationToken),
  ]);
  const matchingInstallation = (entry) =>
    isRecord(entry) && entry.id === installationId && entry.app_id === appId &&
    isRecord(entry.account) &&
    entry.account.id === expectedOwnerAccountId &&
    entry.account.login === 'nohandsai01' &&
    entry.account.type === 'User' &&
    entry.target_id === expectedOwnerAccountId &&
    entry.target_type === 'User' &&
    entry.repository_selection === 'selected' &&
    entry.suspended_at === null &&
    isRecord(entry.permissions) &&
    entry.permissions.checks === 'write' &&
    entry.permissions.pull_requests === 'read' &&
    Array.isArray(entry.events) && entry.events.includes('pull_request');
  assert(matchingInstallation(installation) &&
    matchingInstallation(repositoryInstallation) &&
    isRecord(repository.owner) &&
    repository.id === expectedRepositoryId &&
    repository.full_name === 'nohandsai01/test' &&
    repository.owner.id === expectedOwnerAccountId &&
    repository.owner.login === 'nohandsai01',
  'GUARDIAN_FRESH_INSTALLATION_SCOPE_UNVERIFIED');
  return Object.freeze({
    current: true, installationId, appId,
    ownerAccountId: expectedOwnerAccountId,
    repositoryId: expectedRepositoryId,
  });
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
  postFailureOnlyCheck, verifyOwnerInstallationBinding,
  revalidateCurrentInstallationScope, GuardianApiError };
