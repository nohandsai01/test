'use strict';
// In-process fake HTTPS streams only: no GitHub login, key, socket, or writes.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { readGuardianGithubJson } =
  require('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');

const TARGET = '/installation/repositories?per_page=25&page=1';
const VALID = Buffer.from(JSON.stringify({
  total_count: 1, repositories: [{ full_name: 'nohandsai01/test' }],
}));

async function fakeHttpResponse({ status = 200, length, encoding,
  contentType = 'application/json', incomplete = false, aborted = false,
  body = VALID } = {}) {
  const original = https.request;
  const headers = { 'content-type': contentType };
  if (length !== undefined) headers['content-length'] = length;
  if (encoding !== undefined) headers['content-encoding'] = encoding;
  let observed;
  https.request = (options, onResponse) => {
    observed = { hostname: options.hostname, method: options.method,
      path: options.path, protocol: options.protocol };
    const req = new EventEmitter();
    req.destroy = (error) => req.emit('error', error);
    req.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = status;
      response.headers = headers;
      onResponse(response);
      if (aborted) {
        response.write(body.subarray(0, 8));
        response.emit('aborted');
        response.destroy();
      } else if (incomplete) {
        response.end(body.subarray(0, 5));
      } else {
        response.end(body);
      }
    });
    return req;
  };
  try {
    const response = await readGuardianGithubJson(TARGET,
      'synthetic-token-not-a-secret');
    return { response, observed };
  } finally {
    https.request = original;
  }
}

test('HTTPS reader accepts exact identity JSON response only', async () => {
  const { response, observed } = await fakeHttpResponse({
    length: String(VALID.length),
  });
  assert.equal(response.body.repositories[0].full_name, 'nohandsai01/test');
  assert.deepEqual(observed, {
    hostname: 'api.github.com', method: 'GET', path: TARGET, protocol: 'https:',
  });
});

test('invalid or ambiguous Content-Length rejects before JSON interpretation', async () => {
  for (const length of ['abc', '01', '-1', '12.5', '9007199254740992',
    [], ['5'], '257000']) {
    const expected = length === '257000' ?
      'GITHUB_RESPONSE_TOO_LARGE' : 'GITHUB_CONTENT_LENGTH_INVALID';
    await assert.rejects(fakeHttpResponse({ length }),
      { code: expected });
  }
});

test('short declared body and interrupted streams fail closed', async () => {
  await assert.rejects(fakeHttpResponse({ length: String(VALID.length + 1) }),
    { code: 'GITHUB_RESPONSE_INCOMPLETE' });
  await assert.rejects(fakeHttpResponse({ length: String(VALID.length),
    incomplete: true }), { code: 'GITHUB_RESPONSE_INCOMPLETE' });
  await assert.rejects(fakeHttpResponse({ aborted: true }),
    { code: 'GITHUB_RESPONSE_INCOMPLETE' });
});

test('unsupported encoding, wrong MIME and non-200 status never return evidence', async () => {
  await assert.rejects(fakeHttpResponse({ encoding: 'gzip' }),
    { code: 'GITHUB_CONTENT_ENCODING_INVALID' });
  await assert.rejects(fakeHttpResponse({ contentType: 'text/html' }),
    { code: 'GITHUB_CONTENT_TYPE_INVALID' });
  await assert.rejects(fakeHttpResponse({ status: 302 }),
    { code: 'GITHUB_HTTP_NOT_OK' });
});
