'use strict';
// Entire suite is offline: ephemeral RSA fixture and synthetic HTTPS response.
// It creates no GitHub key, installation, authenticated check, or live request.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const {
  createAppJwt, mintScopedInstallationToken,
  postFailureOnlyCheck, postConclusiveSuccessCheck,
  revalidateCurrentInstallationScope,
} = require('../merge-gate-install/guardian-candidate/github-app-identity.cjs');

const SHA = 'a'.repeat(40);
const APP = 999;
const INSTALL = 42;
const OWNER = 100;
const REPO_ID = 88;
const KEY = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const TOKEN = 'synthetic-credential-32-chars-123456';
function scope() {
  return {
    id: INSTALL, app_id: APP, target_id: OWNER, target_type: 'User',
    account: { id: OWNER, login: 'nohandsai01', type: 'User' },
    repository_selection: 'selected', suspended_at: null,
    permissions: { checks: 'write', pull_requests: 'read', actions: 'read' },
    events: ['pull_request', 'pull_request_review'],
  };
}
function tokenReceipt({ extra = {}, appPermissions = {} } = {}) {
  return {
    token: TOKEN, expires_at: new Date(Date.now() + 25 * 60_000).toISOString(),
    permissions: {
      checks: 'write', pull_requests: 'read', metadata: 'read',
      ...appPermissions,
    },
    repositories: [{ id: REPO_ID, full_name: 'nohandsai01/test' }],
    repository_selection: 'selected', ...extra,
  };
}
function checkReceipt(conclusion) {
  return {
    id: 500, name: 'NO HANDS Merge Gate Required Check',
    head_sha: SHA, status: 'completed', conclusion,
    app: { id: APP },
  };
}
async function fakeAPI(handler, fn) {
  const original = https.request;
  const calls = [];
  https.request = (options, onResponse) => {
    const req = new EventEmitter();
    req.destroy = (error) => req.emit('error', error);
    req.end = (payload) => queueMicrotask(() => {
      const call = { method: options.method, path: options.path,
        hostname: options.hostname, payload };
      calls.push(call);
      let outgoing;
      try { outgoing = handler(call, calls.length); }
      catch (_) { req.emit('error', new Error('synthetic handler failed')); return; }
      const { status = options.method === 'GET' ? 200 : 201,
        response = {}, raw, headers = {}, aborted = false, truncated = false } = outgoing;
      const data = raw === undefined ?
        Buffer.from(JSON.stringify(response)) : Buffer.from(raw);
      const res = new PassThrough();
      res.statusCode = status;
      res.headers = { 'content-type': 'application/json',
        ...headers };
      onResponse(res);
      if (aborted) {
        res.write(data.subarray(0, 5)); res.emit('aborted'); res.destroy();
      } else if (truncated) res.end(data.subarray(0, 5));
      else res.end(data);
    });
    return req;
  };
  try { return await fn(calls); }
  finally { https.request = original; }
}
const baseMint = () => ({
  appId: APP, installationId: INSTALL,
  privateKeyPem: KEY.privateKey, expectedRepositoryId: REPO_ID,
});

test('ephemeral App JWT is RS256 and scoped to exact App ID', () => {
  const jwt = createAppJwt({ appId: APP, privateKeyPem: KEY.privateKey,
    now: Date.parse('2026-10-26T00:00:00Z') });
  const parts = jwt.split('.');
  assert.equal(parts.length, 3);
  assert.equal(JSON.parse(Buffer.from(parts[0], 'base64url')).alg, 'RS256');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(claims.iss, String(APP));
  assert.ok(claims.exp - claims.iat <= 600);
  assert.ok(crypto.verify('RSA-SHA256',
    Buffer.from(parts[0] + '.' + parts[1]), KEY.publicKey,
    Buffer.from(parts[2], 'base64url')));
});

test('mint request uses numeric repository ID and no broad name scope', async () => {
  await fakeAPI((call) => {
    assert.equal(call.method, 'POST');
    assert.equal(call.path, '/app/installations/42/access_tokens');
    const payload = JSON.parse(call.payload);
    assert.deepEqual(payload.repository_ids, [REPO_ID]);
    assert.equal(Object.hasOwn(payload, 'repositories'), false);
    assert.deepEqual(payload.permissions, {
      checks: 'write', pull_requests: 'read', actions: 'read',
    });
    return { response: tokenReceipt({
      appPermissions: { actions: 'read' },
    }) };
  }, async (calls) => {
    const receipt = await mintScopedInstallationToken({
      ...baseMint(), requireActionsRead: true,
    });
    assert.equal(receipt.token, TOKEN);
    assert.equal(receipt.appId, APP);
    assert.equal(calls.length, 1);
  });
});

test('unexpected token permission or malformed bearer fails closed', async () => {
  for (const receipt of [
    tokenReceipt({ appPermissions: { contents: 'write' } }),
    tokenReceipt({ appPermissions: { actions: 'read' } }),
    tokenReceipt({ appPermissions: { metadata: 'write' } }),
    tokenReceipt({ extra: { token: 'bad\nheader' } }),
    tokenReceipt({ extra: { repositories: [
      { id: REPO_ID + 1, full_name: 'nohandsai01/test' },
    ] } }),
    tokenReceipt({ extra: { expires_at:
      new Date(Date.now() + 2 * 3_600_000).toISOString() } }),
  ]) {
    await fakeAPI(() => ({ response: receipt }), async () => {
      await assert.rejects(mintScopedInstallationToken(baseMint()),
        { code: 'GUARDIAN_SCOPED_TOKEN_UNVERIFIED' });
    });
  }
});

test('failure check requires exact App publisher and completed state', async () => {
  await fakeAPI((call) => {
    assert.equal(call.method, 'POST');
    assert.equal(call.path, '/repos/nohandsai01/test/check-runs');
    const payload = JSON.parse(call.payload);
    assert.equal(payload.conclusion, 'failure');
    assert.equal(payload.head_sha, SHA);
    return { response: checkReceipt('failure') };
  }, async (calls) => {
    const result = await postFailureOnlyCheck({
      token: TOKEN, headSha: SHA, summary: 'synthetic HOLD', appId: APP,
    });
    assert.equal(result.checkRunId, 500);
    assert.equal(calls.length, 1);
  });
  for (const bad of [
    { app: { id: APP + 1 } }, { status: 'in_progress' },
    { conclusion: 'success' }, { head_sha: 'b'.repeat(40) },
  ]) {
    await fakeAPI(() => ({
      response: { ...checkReceipt('failure'), ...bad },
    }), async () => {
      await assert.rejects(postFailureOnlyCheck({
        token: TOKEN, headSha: SHA, summary: 'synthetic HOLD', appId: APP,
      }), { code: 'GUARDIAN_FAILURE_CHECK_RECEIPT_INVALID' });
    });
  }
});

test('success writer rejects missing grant before any outbound transport', async () => {
  await fakeAPI(() => {
    throw new Error('unexpected network write');
  }, async (calls) => {
    await assert.rejects(postConclusiveSuccessCheck({
      token: TOKEN, headSha: SHA, appId: APP, summary: 'hold',
    }), { code: 'GUARDIAN_SUCCESS_CHECK_NOT_AUTHORIZED' });
    assert.equal(calls.length, 0);
  });
});

test('positive check response must be completed by exact approved App', async () => {
  await fakeAPI(() => ({ response: checkReceipt('success') }), async () => {
    const result = await postConclusiveSuccessCheck({
      token: TOKEN, headSha: SHA, appId: APP, summary: 'synthetic approved',
      explicitFullModeGrant: 'GUARDIAN_HOST_EXPLICIT_FULL_MODE',
    });
    assert.equal(result.conclusion, 'success');
  });
  await fakeAPI(() => ({ response: {
    ...checkReceipt('success'), status: 'queued',
  } }), async () => {
    await assert.rejects(postConclusiveSuccessCheck({
      token: TOKEN, headSha: SHA, appId: APP, summary: 'synthetic approved',
      explicitFullModeGrant: 'GUARDIAN_HOST_EXPLICIT_FULL_MODE',
    }), { code: 'GUARDIAN_SUCCESS_CHECK_RECEIPT_INVALID' });
  });
});

test('fresh App installation and repository identity verified on fixed GET endpoints', async () => {
  const visited = [];
  await fakeAPI((call) => {
    visited.push(call.path);
    if (call.path === '/app/installations/42' ||
        call.path === '/repos/nohandsai01/test/installation') {
      return { response: scope() };
    }
    if (call.path === '/repos/nohandsai01/test') {
      return { response: { id: REPO_ID, full_name: 'nohandsai01/test',
        owner: { id: OWNER, login: 'nohandsai01' } } };
    }
    throw new Error('unexpected route');
  }, async () => {
    const result = await revalidateCurrentInstallationScope({
      appId: APP, installationId: INSTALL,
      privateKeyPem: KEY.privateKey, installationToken: TOKEN,
      expectedOwnerAccountId: OWNER, expectedRepositoryId: REPO_ID,
      requireActionsRead: true,
    });
    assert.equal(result.current, true);
    assert.deepEqual(visited.sort(), [
      '/app/installations/42',
      '/repos/nohandsai01/test',
      '/repos/nohandsai01/test/installation',
    ].sort());
  });
});

test('duplicate JSON key, invalid length, truncated and non-201 POST all reject', async () => {
  const invalid = [
    { raw: '{"id":500,"id":500}' },
    { headers: { 'content-length': '01' }, response: checkReceipt('failure') },
    { headers: { 'content-length': '1000' }, response: checkReceipt('failure') },
    { aborted: true, response: checkReceipt('failure') },
    { headers: { 'content-encoding': 'gzip' }, response: checkReceipt('failure') },
    { status: 200, response: checkReceipt('failure') },
  ];
  for (const spec of invalid) {
    await fakeAPI(() => spec, async () => {
      await assert.rejects(postFailureOnlyCheck({
        token: TOKEN, headSha: SHA, summary: 'synthetic HOLD', appId: APP,
      }));
    });
  }
});
