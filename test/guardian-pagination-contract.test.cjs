'use strict';
// Synthetic, read-only GitHub API pagination contract; NO live credentials.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { collectAuthenticatedGithubSnapshot } =
  require('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
const REPO = 'nohandsai01/test';
const SHA = 'a'.repeat(40);
const PREFIX = '/repos/nohandsai01/test';

async function mockRead({ changeCheckPage2 = false, changeInstallPage2 = false } = {}) {
  const original = https.request;
  const calls = new Map();
  const visited = [];
  const installationRepos = Array.from({length: 26}, (_, i) =>
    ({full_name: i === 25 ? REPO : 'org/source-' + i}));
  const checkRuns = Array.from({length: 26}, (_, i) => ({
    id: i + 1, name: 'synthetic-' + i, head_sha: SHA,
    app: { id: 777 }, check_suite: { id: 44 },
    status: 'completed', conclusion: 'success',
    completed_at: '2026-10-23T12:01:00Z',
  }));
  https.request = (request, onResponse) => {
    const req = new EventEmitter();
    req.end = () => queueMicrotask(() => {
      const path = request.path;
      const count = (calls.get(path) || 0) + 1;
      calls.set(path, count);
      visited.push({path, method: request.method, host: request.hostname});
      const search = path.match(/[?&]page=(\d+)/);
      const page = search ? Number(search[1]) : 1;
      let body, link = '';
      if (path.startsWith('/installation/repositories?')) {
        const rows = installationRepos.slice((page - 1) * 25, page * 25)
          .map((x) => ({...x}));
        if (changeInstallPage2 && page === 2 && count === 2) {
          rows[0].full_name = 'org/revoked-during-read';
        }
        body = { total_count: 26, repositories: rows };
        if (page === 1) link =
          '<https://api.github.com/installation/repositories?page=2>; rel="next"';
      } else if (path === PREFIX + '/pulls/12') {
        body = { number: 12, state: 'open', draft: false, changed_files: 2,
          commits: 1, user: {id: 111, login: 'synthetic', type: 'User'},
          base: {ref: 'main', repo: {full_name: REPO}},
          head: {sha: SHA, repo: {full_name: REPO}} };
      } else if (path === PREFIX + '/commits/' + SHA +
        '/check-suites?per_page=1&page=1') {
        body = { total_count: 1, check_suites: [{id: 44}] };
      } else if (path.startsWith(PREFIX + '/commits/' + SHA +
        '/check-runs?filter=all&per_page=25&page=')) {
        const rows = checkRuns.slice((page - 1) * 25, page * 25)
          .map((x) => ({...x}));
        if (changeCheckPage2 && page === 2 && count === 2) {
          rows[0].conclusion = 'failure';
        }
        body = { total_count: 26, check_runs: rows };
        if (page === 1) link =
          '<https://api.github.com/repos/nohandsai01/test/commits/' +
          SHA + '/check-runs?page=2>; rel="next"';
      } else {
        req.emit('error', new Error('Unexpected mocked GET'));
        return;
      }
      const bytes = Buffer.from(JSON.stringify(body));
      const res = new PassThrough();
      res.statusCode = 200;
      res.headers = {'content-type': 'application/json',
        'content-length': String(bytes.length), link };
      onResponse(res);
      res.end(bytes);
    });
    req.destroy = (error) => req.emit('error', error);
    return req;
  };
  try {
    const snapshot = await collectAuthenticatedGithubSnapshot({
      pullNumber: 12, expectedHeadSha: SHA,
      installationToken: 'synthetic-readonly-credential',
    });
    return {snapshot, visited, calls};
  } finally {
    https.request = original;
  }
}

test('two-page installation scope and check-run inventory are fully re-read', async () => {
  const {snapshot, visited, calls} = await mockRead();
  assert.equal(snapshot.checkRuns.total_count, 26);
  assert.equal(snapshot.checkRuns.check_runs.length, 26);
  const scopePage2 = '/installation/repositories?per_page=25&page=2';
  const checksPage2 = PREFIX + '/commits/' + SHA +
    '/check-runs?filter=all&per_page=25&page=2';
  assert.equal(calls.get(scopePage2), 2);
  assert.equal(calls.get(checksPage2), 2);
  assert.ok(visited.every(({method, host}) =>
    method === 'GET' && host === 'api.github.com'));
});

test('changing second-page installation scope fails closed', async () => {
  await assert.rejects(mockRead({changeInstallPage2: true}),
    {code: 'GITHUB_INSTALLATION_PAGE_CHANGED'});
});

test('changing second-page check conclusion fails closed with same row count', async () => {
  await assert.rejects(mockRead({changeCheckPage2: true}),
    {code: 'GITHUB_CHECKS_CHANGED_DURING_READ'});
});
