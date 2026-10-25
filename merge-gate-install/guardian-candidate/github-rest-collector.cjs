/**
 * Read-only, fail-closed GitHub REST collector for a future Guardian App host.
 * Only hardcoded api.github.com routes are used; no caller-controlled URLs,
 * redirects, unauthenticated fallback, writes, or check-run issuance.
 */
'use strict';

const https = require('node:https');
const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');

const REPO = 'nohandsai01/test';
const PREFIX = '/repos/nohandsai01/test';
const SHA = /^[0-9a-f]{40}$/;
// The shared strict JSON decoder rejects bodies above 256,000 bytes.
// Smaller pages bound both decoding cost and the risk of parser truncation.
const MAX_RESPONSE_BYTES = 256_000;
const PER_PAGE = 25;
const MAX_CHECKS = 1000;
const MAX_INSTALLATION_REPOS = 500;

class CollectorError extends Error {
  constructor(code) { super(code); this.name = 'CollectorError'; this.code = code; }
}
function guard(condition, code) {
  if (!condition) throw new CollectorError(code);
}
function object(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

// The installation token must originate in a separately managed, read-only
// GitHub App credential runtime. It is never persisted or returned.
function getJson(path, installationToken) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      protocol: 'https:', hostname: 'api.github.com', port: 443,
      method: 'GET', path, timeout: 10_000,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: 'Bearer ' + installationToken,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'nohands-guardian-source-only/1',
      },
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new CollectorError('GITHUB_HTTP_NOT_OK'));
        return;
      }
      const contentType = response.headers['content-type'];
      if (typeof contentType !== 'string' ||
          !/^application\/(json|vnd\.github\+json)(;|$)/i.test(contentType)) {
        response.resume();
        reject(new CollectorError('GITHUB_CONTENT_TYPE_INVALID'));
        return;
      }
      // The response must be identity-encoded JSON. Never parse compressed
      // bytes or accept ambiguous/invalid framing metadata as trusted data.
      const encoding = response.headers['content-encoding'];
      if (encoding !== undefined && encoding !== 'identity') {
        response.resume();
        reject(new CollectorError('GITHUB_CONTENT_ENCODING_INVALID'));
        return;
      }
      const lengthHeader = response.headers['content-length'];
      if (lengthHeader !== undefined &&
          (typeof lengthHeader !== 'string' ||
           !/^(0|[1-9][0-9]*)$/.test(lengthHeader) ||
           !Number.isSafeInteger(Number(lengthHeader)))) {
        response.resume();
        reject(new CollectorError('GITHUB_CONTENT_LENGTH_INVALID'));
        return;
      }
      const declared = lengthHeader === undefined ? null : Number(lengthHeader);
      if (declared !== null && declared > MAX_RESPONSE_BYTES) {
        response.resume();
        reject(new CollectorError('GITHUB_RESPONSE_TOO_LARGE'));
        return;
      }
      let size = 0, ended = false;
      const chunks = [];
      if (typeof response.setTimeout === 'function') {
        response.setTimeout(10_000, () =>
          response.destroy(new CollectorError('GITHUB_READ_TIMEOUT')));
      }
      response.on('data', (chunk) => {
        if (!Buffer.isBuffer(chunk)) {
          response.destroy(new CollectorError('GITHUB_RESPONSE_INVALID_CHUNK'));
          return;
        }
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES ||
            (declared !== null && size > declared)) {
          response.destroy(new CollectorError('GITHUB_RESPONSE_TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('aborted', () =>
        reject(new CollectorError('GITHUB_RESPONSE_INCOMPLETE')));
      response.on('close', () => {
        if (!ended) reject(new CollectorError('GITHUB_RESPONSE_INCOMPLETE'));
      });
      response.on('error', (error) => reject(error instanceof CollectorError ?
        error : new CollectorError('GITHUB_TRANSPORT_FAILED')));
      response.on('end', () => {
        ended = true;
        if (declared !== null && size !== declared) {
          reject(new CollectorError('GITHUB_RESPONSE_INCOMPLETE'));
          return;
        }
        try {
          const body = parseUniqueKeySourceLock(Buffer.concat(chunks));
          resolve({ body, link: response.headers.link || '' });
        } catch (_) {
          reject(new CollectorError('GITHUB_JSON_INVALID'));
        }
      });
    });
    req.on('timeout', () => req.destroy(new CollectorError('GITHUB_READ_TIMEOUT')));
    req.on('error', (error) => reject(error instanceof CollectorError ? error :
      new CollectorError('GITHUB_TRANSPORT_FAILED')));
    req.end();
  });
}

function normalizedPr(raw) {
  guard(object(raw) && Number.isSafeInteger(raw.number) && raw.number > 0 &&
    (raw.state === 'open' || raw.state === 'closed') && object(raw.base) &&
    object(raw.head) && object(raw.base.repo) && object(raw.head.repo) &&
    object(raw.user) && Number.isSafeInteger(raw.user.id) && raw.user.id > 0 &&
    raw.user.type === 'User' && typeof raw.user.login === 'string' &&
    raw.user.login.length > 0 &&
    typeof raw.base.ref === 'string' && raw.base.ref === 'main' &&
    typeof raw.base.sha === 'string' && SHA.test(raw.base.sha) &&
    typeof raw.head.ref === 'string' && raw.head.ref.length > 0 &&
    typeof raw.head.sha === 'string' && SHA.test(raw.head.sha) &&
    raw.base.repo.full_name === REPO && raw.head.repo.full_name === REPO &&
    typeof raw.draft === 'boolean' &&
    Number.isSafeInteger(raw.changed_files) && raw.changed_files >= 0 &&
    raw.changed_files <= 3000 &&
    Number.isSafeInteger(raw.commits) && raw.commits >= 1,
  'GITHUB_PR_RESPONSE_INVALID');
  return {
    number: raw.number,
    state: raw.state,
    draft: raw.draft,
    // A bounded count from GitHub's PR endpoint is independent of the
    // paginated files endpoint and guards against omitted protected files.
    changedFiles: raw.changed_files,
    commitCount: raw.commits,
    author: { id: raw.user.id, login: raw.user.login, type: raw.user.type },
    base: { ref: raw.base.ref, sha: raw.base.sha,
      repo: { full_name: raw.base.repo.full_name } },
    head: { ref: raw.head.ref, sha: raw.head.sha,
      repo: { full_name: raw.head.repo.full_name } },
  };
}
function normalizedCheck(raw) {
  guard(object(raw) && object(raw.app) && object(raw.check_suite) &&
    Number.isSafeInteger(raw.id) && raw.id > 0 &&
    Number.isSafeInteger(raw.app.id) && raw.app.id > 0 &&
    Number.isSafeInteger(raw.check_suite.id) && raw.check_suite.id > 0 &&
    typeof raw.name === 'string' && raw.name.length > 0 &&
    raw.name.length <= 120 && !/[\x00-\x1f]/.test(raw.name) &&
    typeof raw.head_sha === 'string' && SHA.test(raw.head_sha) &&
    ['queued', 'in_progress', 'completed'].includes(raw.status) &&
    (raw.status !== 'completed' ||
      (typeof raw.completed_at === 'string' &&
        Number.isFinite(Date.parse(raw.completed_at)))),
  'GITHUB_CHECK_RESPONSE_INVALID');
  return {
    id: raw.id, name: raw.name, head_sha: raw.head_sha,
    app: { id: raw.app.id }, status: raw.status,
    check_suite: { id: raw.check_suite.id },
    conclusion: raw.conclusion, completed_at: raw.completed_at,
  };
}
function nextPage(link) {
  guard(typeof link === 'string' && link.length < 10_000, 'GITHUB_PAGINATION_INVALID');
  return /(?:^|,)\s*<[^>]+>\s*;\s*rel="next"(?:\s*,|\s*$)/.test(link);
}
function countResponse(response, arrayName, limit) {
  const { body } = response;
  guard(object(body) && Number.isSafeInteger(body.total_count) &&
    body.total_count >= 0 && body.total_count <= limit &&
    Array.isArray(body[arrayName]), 'GITHUB_PAGE_COUNT_INVALID');
  return body.total_count;
}

async function confirmInstallationScope(token) {
  const first = await getJson('/installation/repositories?per_page=25&page=1', token);
  const total = countResponse(first, 'repositories', MAX_INSTALLATION_REPOS);
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  let found = false;
  let fetched = 0;
  const observedPages = [];
  for (let page = 1; page <= pages; page++) {
    const pagePath = '/installation/repositories?per_page=25&page=' + page;
    const response = page === 1 ? first : await getJson(pagePath, token);
    guard(countResponse(response, 'repositories', MAX_INSTALLATION_REPOS) === total,
      'GITHUB_INSTALLATION_PAGE_CHANGED');
    const expected = Math.min(PER_PAGE, total - fetched);
    guard(response.body.repositories.length === expected &&
      nextPage(response.link) === (page < pages), 'GITHUB_INSTALLATION_PAGE_INCOMPLETE');
    observedPages.push({ path: pagePath, bytes: JSON.stringify(response.body),
      link: response.link });
    for (const repo of response.body.repositories) {
      guard(object(repo) && typeof repo.full_name === 'string',
        'GITHUB_INSTALLATION_REPO_INVALID');
      if (repo.full_name === REPO) found = true;
    }
    fetched += expected;
  }
  // A repository can be removed from an installation while later pages are
  // read. Re-check each page and its pagination metadata before accepting scope.
  for (const original of observedPages) {
    const repeat = await getJson(original.path, token);
    guard(JSON.stringify(repeat.body) === original.bytes &&
      repeat.link === original.link, 'GITHUB_INSTALLATION_PAGE_CHANGED');
  }
  guard(found, 'GITHUB_APP_INSTALLATION_SCOPE_MISMATCH');
}

async function collectAuthenticatedGithubSnapshot({ pullNumber, expectedHeadSha, installationToken }) {
  guard(Number.isSafeInteger(pullNumber) && pullNumber > 0 &&
    typeof expectedHeadSha === 'string' && SHA.test(expectedHeadSha),
  'COLLECTOR_TARGET_INVALID');
  guard(typeof installationToken === 'string' && installationToken.length >= 8 &&
    installationToken.length <= 4096 && /^[\x21-\x7e]+$/.test(installationToken),
  'COLLECTOR_APP_TOKEN_UNAVAILABLE');

  await confirmInstallationScope(installationToken);
  const prPath = PREFIX + '/pulls/' + pullNumber;
  const firstPr = normalizedPr((await getJson(prPath, installationToken)).body);
  guard(firstPr.number === pullNumber && firstPr.state === 'open' &&
    firstPr.base.ref === 'main' && firstPr.base.repo.full_name === REPO &&
    firstPr.head.repo.full_name === REPO && firstPr.head.sha === expectedHeadSha,
  'GITHUB_PR_SCOPE_OR_SHA_MISMATCH');

  // Direct check-run enumeration is capped by GitHub at 1000 check suites;
  // deliberately HOLD rather than claim complete evidence at that boundary.
  const suites = await getJson(PREFIX + '/commits/' + expectedHeadSha +
    '/check-suites?per_page=1&page=1', installationToken);
  const suiteCount = countResponse(suites, 'check_suites', 999);
  guard(suites.body.check_suites.length === Math.min(suiteCount, 1),
    'GITHUB_SUITE_COUNT_INCOMPLETE');

  const runsPath = PREFIX + '/commits/' + expectedHeadSha + '/check-runs?filter=all&per_page=25&page=';
  const first = await getJson(runsPath + '1', installationToken);
  const total = countResponse(first, 'check_runs', MAX_CHECKS);
  // GitHub may truncate ref-based check enumeration at 1000. Exact boundary
  // cannot prove an exhaustive list; never accept a capped collection.
  guard(total < MAX_CHECKS, 'GITHUB_CHECK_ENUMERATION_AT_CAP');
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const runs = [];
  const ids = new Set(), observedPages = [];
  for (let page = 1; page <= pages; page++) {
    const pagePath = runsPath + page;
    const response = page === 1 ? first : await getJson(pagePath, installationToken);
    guard(countResponse(response, 'check_runs', MAX_CHECKS) === total,
      'GITHUB_CHECK_PAGE_CHANGED');
    guard(response.body.check_runs.length === Math.min(PER_PAGE, total - runs.length) &&
      nextPage(response.link) === (page < pages), 'GITHUB_CHECK_PAGE_INCOMPLETE');
    observedPages.push({ path: pagePath, bytes: JSON.stringify(response.body),
      link: response.link });
    for (const raw of response.body.check_runs) {
      const run = normalizedCheck(raw);
      guard(Number.isSafeInteger(run.id) && run.id > 0 && !ids.has(run.id) &&
        run.head_sha === expectedHeadSha, 'GITHUB_CHECK_DUPLICATE_OR_WRONG_SHA');
      ids.add(run.id);
      runs.push(run);
    }
  }
  guard(runs.length === total, 'GITHUB_CHECK_PAGE_INCOMPLETE');

  // A later check-suite rerun can change page 2 without changing page 1.
  // Re-read ALL pages, including an empty first page, and compare raw rows,
  // counts and links. This is not an atomic snapshot or proof of issuer trust.
  for (const original of observedPages) {
    const repeat = await getJson(original.path, installationToken);
    guard(countResponse(repeat, 'check_runs', MAX_CHECKS) === total &&
      JSON.stringify(repeat.body) === original.bytes &&
      repeat.link === original.link,
    'GITHUB_CHECKS_CHANGED_DURING_READ');
  }
  // New check suites may appear without changing already-enumerated pages;
  // an installation can also lose repository access mid-enumeration.
  const finalSuites = await getJson(PREFIX + '/commits/' + expectedHeadSha +
    '/check-suites?per_page=1&page=1', installationToken);
  guard(JSON.stringify(finalSuites.body) === JSON.stringify(suites.body) &&
    finalSuites.link === suites.link,
  'GITHUB_SUITES_CHANGED_DURING_READ');
  const finalPr = normalizedPr((await getJson(prPath, installationToken)).body);
  guard(JSON.stringify(finalPr) === JSON.stringify(firstPr),
    'GITHUB_PR_CHANGED_DURING_READ');
  await confirmInstallationScope(installationToken);

  return {
    repository: REPO,
    pullRequest: finalPr,
    checkRuns: { total_count: total, check_runs: runs },
  };
}

// This bounded reader is internal infrastructure for the independently
// authenticated provenance collector; it never sends arbitrary HTTP origins.
module.exports = { collectAuthenticatedGithubSnapshot, CollectorError,
  readGuardianGithubJson: getJson };
