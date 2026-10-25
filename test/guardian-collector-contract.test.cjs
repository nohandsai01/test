'use strict';

// Synthetic HTTPS-only contract checks: never contacts GitHub or mints a token.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { collectAuthenticatedGithubSnapshot } =
  require('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');

const REPO = 'nohandsai01/test';
const SHA = 'a'.repeat(40);

async function collectWithSyntheticGithub({ changedFiles = 2, commits = 3,
  changedFilesOnReread = changedFiles, commitsOnReread = commits } = {}) {
  const original = https.request;
  const visited = [];
  let pullReads = 0;
  https.request = (request, onResponse) => {
    const req = new EventEmitter();
    req.end = () => queueMicrotask(() => {
      const endpoint = request.path;
      visited.push({ endpoint, method: request.method, host: request.hostname });
      let payload;
      if (endpoint === '/installation/repositories?per_page=25&page=1') {
        payload = { total_count: 1, repositories: [{ full_name: REPO }] };
      } else if (endpoint === '/repos/nohandsai01/test/pulls/12') {
        const repeat = pullReads++ > 0;
        payload = {
          number: 12, state: 'open', draft: false,
          changed_files: repeat ? changedFilesOnReread : changedFiles,
          commits: repeat ? commitsOnReread : commits,
          user: { id: 111, login: 'synthetic', type: 'User' },
          base: { ref: 'main', repo: { full_name: REPO } },
          head: { sha: SHA, repo: { full_name: REPO } },
        };
      } else if (endpoint === '/repos/nohandsai01/test/commits/' +
        SHA + '/check-suites?per_page=1&page=1') {
        payload = { total_count: 0, check_suites: [] };
      } else if (endpoint === '/repos/nohandsai01/test/commits/' +
        SHA + '/check-runs?filter=all&per_page=25&page=1') {
        payload = { total_count: 0, check_runs: [] };
      } else {
        req.emit('error', new Error('unexpected endpoint'));
        return;
      }
      const bytes = Buffer.from(JSON.stringify(payload));
      const res = new PassThrough();
      res.statusCode = 200;
      res.headers = { 'content-type': 'application/json',
        'content-length': String(bytes.length) };
      onResponse(res);
      res.end(bytes);
    });
    req.destroy = (err) => req.emit('error', err);
    return req;
  };
  try {
    const snapshot = await collectAuthenticatedGithubSnapshot({
      pullNumber: 12, expectedHeadSha: SHA,
      installationToken: 'synthetic-read-only-token',
    });
    return { snapshot, visited };
  } finally {
    https.request = original;
  }
}

test('collector binds PR independent file and commit totals to snapshot', async () => {
  const { snapshot, visited } = await collectWithSyntheticGithub();
  assert.equal(snapshot.pullRequest.changedFiles, 2);
  assert.equal(snapshot.pullRequest.commitCount, 3);
  assert.equal(snapshot.pullRequest.head.sha, SHA);
  assert.equal(snapshot.checkRuns.total_count, 0);
  assert.equal(visited.filter((v) =>
    v.endpoint === '/repos/nohandsai01/test/pulls/12').length, 2);
  assert.ok(visited.every((v) => v.method === 'GET' &&
    v.host === 'api.github.com'));
});

test('collector rejects malformed PR counts before any positive snapshot', async () => {
  for (const changedFiles of [null, -1, '2', 3001, 1.5]) {
    await assert.rejects(collectWithSyntheticGithub({ changedFiles }),
      { code: 'GITHUB_PR_RESPONSE_INVALID' });
  }
  for (const commits of [null, 0, -1, '3', 1.1]) {
    await assert.rejects(collectWithSyntheticGithub({ commits }),
      { code: 'GITHUB_PR_RESPONSE_INVALID' });
  }
});

test('collector refuses count drift between authenticated PR reads', async () => {
  await assert.rejects(collectWithSyntheticGithub({ changedFilesOnReread: 3 }),
    { code: 'GITHUB_PR_CHANGED_DURING_READ' });
  await assert.rejects(collectWithSyntheticGithub({ commitsOnReread: 4 }),
    { code: 'GITHUB_PR_CHANGED_DURING_READ' });
});
