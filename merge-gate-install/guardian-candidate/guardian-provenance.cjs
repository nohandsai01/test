/**
 * Fail-closed provenance for an opt-in, independently hosted Guardian App.
 * GitHub API reads are authenticated with the repository-scoped App token.
 * Neither workflow conclusions nor PR-authored JSON are themselves authority.
 * Importing this module performs no I/O.
 */
'use strict';

const { readGuardianGithubJson } = require('./github-rest-collector.cjs');
const PREFIX = '/repos/nohandsai01/test';
const SHA = /^[0-9a-f]{40}$/;
const CHECK = 'NO HANDS Merge Gate Required Check';

class GuardianProvenanceError extends Error {
  constructor(code) { super(code); this.name = 'GuardianProvenanceError'; this.code = code; }
}
function requireProof(ok, code) {
  if (!ok) throw new GuardianProvenanceError(code);
}
function object(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function positive(x) { return Number.isSafeInteger(x) && x > 0; }
function timestamp(x) {
  return typeof x === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(x) &&
    Number.isFinite(Date.parse(x));
}
function nextPage(link) {
  requireProof(typeof link === 'string' && link.length < 10_000,
    'GUARDIAN_PROVENANCE_LINK_INVALID');
  return /(?:^|,)\s*<[^>]+>\s*;\s*rel="next"(?:\s*,|\s*$)/.test(link);
}

async function pagesArray(path, token, limit) {
  const rows = [];
  for (let page = 1; page <= Math.ceil(limit / 25) + 1; page++) {
    const response = await readGuardianGithubJson(path +
      (path.includes('?') ? '&' : '?') + 'per_page=25&page=' + page, token);
    requireProof(Array.isArray(response.body) && response.body.length <= 25,
      'GUARDIAN_PROVENANCE_PAGE_INVALID');
    rows.push(...response.body);
    requireProof(rows.length <= limit, 'GUARDIAN_PROVENANCE_PAGE_LIMIT');
    const more = nextPage(response.link);
    requireProof(!more || response.body.length === 25,
      'GUARDIAN_PROVENANCE_PAGINATION_INCOMPLETE');
    if (!more) return rows;
  }
  throw new GuardianProvenanceError('GUARDIAN_PROVENANCE_PAGINATION_LIMIT');
}

async function pagesCounted(path, key, token, limit) {
  const rows = [];
  let total = null;
  for (let page = 1; page <= Math.ceil(limit / 25) + 1; page++) {
    const response = await readGuardianGithubJson(path +
      (path.includes('?') ? '&' : '?') + 'per_page=25&page=' + page, token);
    const body = response.body;
    requireProof(object(body) && positive(body.total_count + 1) &&
      body.total_count <= limit && Array.isArray(body[key]),
    'GUARDIAN_PROVENANCE_COUNT_INVALID');
    if (total === null) total = body.total_count;
    requireProof(body.total_count === total &&
      body[key].length === Math.min(25, total - rows.length) &&
      nextPage(response.link) === (rows.length + body[key].length < total),
    'GUARDIAN_PROVENANCE_PAGE_CHANGED');
    rows.push(...body[key]);
    if (rows.length === total) return rows;
  }
  throw new GuardianProvenanceError('GUARDIAN_PROVENANCE_PAGINATION_LIMIT');
}

function reviewEvidence(reviews, release, authorId, headSha) {
  const latest = new Map(), ids = new Set();
  for (const review of reviews) {
    requireProof(object(review) && positive(review.id) && !ids.has(review.id) &&
      object(review.user) && positive(review.user.id) &&
      ['APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED', 'PENDING'].includes(review.state) &&
      (review.state === 'PENDING' || timestamp(review.submitted_at)),
    'GUARDIAN_REVIEW_RESPONSE_INVALID');
    ids.add(review.id);
    if (review.state === 'PENDING') continue;
    const prior = latest.get(review.user.id);
    if (!prior || Date.parse(review.submitted_at) > Date.parse(prior.submitted_at) ||
        (review.submitted_at === prior.submitted_at && review.id > prior.id)) {
      latest.set(review.user.id, review);
    }
  }
  let approvals = 0;
  for (const id of release.reviewerIds) {
    const review = latest.get(id);
    if (review && id !== authorId && review.user.type === 'User' &&
        review.state === 'APPROVED' && review.commit_id === headSha) approvals++;
    if (review?.state === 'CHANGES_REQUESTED') {
      throw new GuardianProvenanceError('GUARDIAN_REVIEW_CHANGES_REQUESTED');
    }
  }
  requireProof(approvals >= release.minApprovals,
    'GUARDIAN_INDEPENDENT_EXACT_HEAD_APPROVALS_MISSING');
  return approvals;
}

function branchRulesEvidence(rules, appId, minimumApprovals, expectedEvidence) {
  requireProof(Array.isArray(rules), 'GUARDIAN_BRANCH_RULES_UNAVAILABLE');
  requireProof(Array.isArray(expectedEvidence) && expectedEvidence.length === 2 &&
    new Set(expectedEvidence.map((item) => item?.type)).size === 2 &&
    expectedEvidence.every((item) => object(item) &&
      ['tests', 'ci'].includes(item.type) &&
      typeof item.checkName === 'string' && item.checkName.length > 0 &&
      item.checkName !== CHECK && positive(item.issuerAppId) &&
      item.issuerAppId !== appId) &&
    new Set(expectedEvidence.map((item) => item.checkName)).size === 2,
  'GUARDIAN_SIGNED_REQUIRED_CHECK_BINDINGS_INVALID');
  const requiredContexts = new Set([CHECK,
    ...expectedEvidence.map((item) => item.checkName)]);
  const bindings = [];
  const reviewProtections = [];
  for (const rule of rules) {
    if (!object(rule)) continue;
    if (rule.type === 'pull_request') {
      requireProof(object(rule.parameters), 'GUARDIAN_BRANCH_REVIEW_RULE_MALFORMED');
      reviewProtections.push(rule.parameters);
      continue;
    }
    if (rule.type !== 'required_status_checks') continue;
    requireProof(object(rule.parameters), 'GUARDIAN_BRANCH_RULES_MALFORMED');
    const list = rule.parameters.required_status_checks;
    requireProof(Array.isArray(list), 'GUARDIAN_BRANCH_RULES_MALFORMED');
    bindings.push(...list.filter((item) =>
      object(item) && requiredContexts.has(item.context)));
  }
  const guardianBindings = bindings.filter((item) => item.context === CHECK);
  requireProof(guardianBindings.length === 1 &&
    guardianBindings[0].integration_id === appId,
    'GUARDIAN_REQUIRED_CHECK_APP_NOT_PINNED');
  // The Guardian's success conclusion is a point-in-time snapshot. GitHub
  // itself must also require both signed underlying workflows, so a same-SHA
  // CI rerun failure cannot leave an old Guardian success as the sole gate.
  for (const evidence of expectedEvidence) {
    const matches = bindings.filter((item) => item.context === evidence.checkName);
    requireProof(matches.length === 1 &&
      matches[0].integration_id === evidence.issuerAppId,
    'GUARDIAN_EVIDENCE_REQUIRED_CHECK_APP_NOT_PINNED');
  }
  // GitHub must independently enforce reviews even after a positive check:
  // an approval can be dismissed later without changing the commit SHA.
  requireProof(reviewProtections.some((parameters) =>
    Number.isSafeInteger(parameters.required_approving_review_count) &&
    parameters.required_approving_review_count >= minimumApprovals &&
    parameters.dismiss_stale_reviews_on_push === true &&
    parameters.require_last_push_approval === true),
  'GUARDIAN_GITHUB_REVIEW_PROTECTION_NOT_ENFORCED');
}

async function rulesetBypassEvidence(rules, token) {
  // Effective branch rules identify the rulesets that GitHub applies to main,
  // but do not expose the actors permitted to bypass those rules. Never
  // confuse an omitted bypass_actors property with an empty list: GitHub
  // deliberately hides it from installations without ruleset write access.
  const ids = new Set();
  for (const rule of rules) {
    requireProof(object(rule) && positive(rule.ruleset_id) &&
      rule.ruleset_source_type === 'Repository' &&
      rule.ruleset_source === 'nohandsai01/test',
    'GUARDIAN_ACTIVE_RULESET_IDENTITY_UNVERIFIED');
    ids.add(rule.ruleset_id);
  }
  requireProof(ids.size > 0, 'GUARDIAN_ACTIVE_RULESET_IDENTITY_UNVERIFIED');
  for (const id of ids) {
    const response = await readGuardianGithubJson(PREFIX + '/rulesets/' + id,
      token);
    requireProof(!nextPage(response.link) && object(response.body) &&
      response.body.id === id && response.body.target === 'branch' &&
      response.body.source_type === 'Repository' &&
      response.body.source === 'nohandsai01/test' &&
      response.body.enforcement === 'active',
    'GUARDIAN_ACTIVE_RULESET_IDENTITY_UNVERIFIED');
    requireProof(Array.isArray(response.body.bypass_actors),
      'GUARDIAN_RULESET_BYPASS_ACTORS_UNOBSERVABLE');
    requireProof(response.body.bypass_actors.length === 0,
      'GUARDIAN_RULESET_BYPASS_ACTORS_PRESENT');
  }
}

function candidateScopedPath(filename) {
  // GitHub rename entries contain two paths. Both must satisfy the same
  // restriction: a protected source cannot be moved into an allowed folder.
  return typeof filename === 'string' && filename.length < 500 &&
    /^(src|test|docs)\/[A-Za-z0-9._/\-]+$/.test(filename) &&
    filename.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..');
}

function validateTouchedFiles(files) {
  requireProof(files.length > 0, 'GUARDIAN_PR_NO_CHANGED_FILES');
  const seen = new Set();
  for (const file of files) {
    requireProof(object(file) && typeof file.filename === 'string' &&
      file.filename.length < 500 && !seen.has(file.filename) &&
      ['added', 'modified', 'removed', 'renamed', 'copied', 'changed'].includes(file.status),
    'GUARDIAN_PR_FILE_RESPONSE_INVALID');
    seen.add(file.filename);
    // Workflow source must not be supplied or changed by the PR author.
    // A renamed source is a two-path change: validate its old and new names.
    requireProof(candidateScopedPath(file.filename) &&
      (file.status !== 'renamed' || candidateScopedPath(file.previous_filename)),
    'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE');
  }
}

async function workflowJobProof({ token, headSha, check, binding }) {
  const runs = await pagesCounted(PREFIX + '/actions/workflows/' +
    binding.workflowId + '/runs?head_sha=' + headSha, 'workflow_runs', token, 60);
  const linked = runs.filter((run) => object(run) &&
    run.check_suite_id === check.check_suite?.id);
  requireProof(linked.length === 1, 'GUARDIAN_WORKFLOW_RUN_AMBIGUOUS');
  const run = linked[0];
  requireProof(positive(run.id) && run.workflow_id === binding.workflowId &&
    run.head_sha === headSha && run.event === binding.event &&
    run.status === 'completed' && run.conclusion === 'success' &&
    positive(run.run_attempt) && timestamp(run.created_at) &&
    timestamp(run.updated_at) && Date.parse(run.updated_at) >= Date.parse(run.created_at) &&
    object(run.repository) && run.repository.full_name === 'nohandsai01/test',
  'GUARDIAN_WORKFLOW_RUN_INVALID');
  const jobs = await pagesCounted(PREFIX + '/actions/runs/' +
    run.id + '/jobs?filter=latest', 'jobs', token, 200);
  const matched = jobs.filter((job) => object(job) &&
    job.check_run_url === 'https://api.github.com' + PREFIX + '/check-runs/' + check.id);
  requireProof(matched.length === 1 && matched[0].run_id === run.id &&
    matched[0].head_sha === headSha && matched[0].name === check.name &&
    matched[0].status === 'completed' && matched[0].conclusion === 'success' &&
    matched[0].run_attempt === run.run_attempt &&
    timestamp(matched[0].completed_at),
  'GUARDIAN_CHECK_NOT_ASSOCIATED_WITH_WORKFLOW_JOB');
  return { workflowId: binding.workflowId, runId: run.id,
    jobId: matched[0].id, checkRunId: check.id };
}

async function collectGuardianConclusiveProvenance({ pullNumber, headSha,
  installationToken, snapshot, releasePolicy, expectedEvidence, guardianAppId }) {
  requireProof(positive(pullNumber) && SHA.test(headSha) &&
    typeof installationToken === 'string' && installationToken.length >= 16 &&
    object(snapshot) && object(snapshot.pullRequest) &&
    object(snapshot.checkRuns) && object(releasePolicy) &&
    Array.isArray(expectedEvidence) && expectedEvidence.length === 2 &&
    releasePolicy.guardianAppId === guardianAppId && positive(guardianAppId),
  'GUARDIAN_CONCLUSIVE_INPUT_INVALID');
  const pr = snapshot.pullRequest;
  requireProof(pr.number === pullNumber && pr.state === 'open' &&
    pr.draft === false && pr.head?.sha === headSha &&
    positive(pr.author?.id) && pr.author.type === 'User',
  'GUARDIAN_PR_NOT_REVIEWABLE_AT_HEAD');

  const [commits, reviews, files, rules] = await Promise.all([
    pagesArray(PREFIX + '/pulls/' + pullNumber + '/commits', installationToken, 250),
    pagesArray(PREFIX + '/pulls/' + pullNumber + '/reviews', installationToken, 500),
    pagesArray(PREFIX + '/pulls/' + pullNumber + '/files', installationToken, 300),
    readGuardianGithubJson(PREFIX + '/rules/branches/main', installationToken),
  ]);
  requireProof(!nextPage(rules.link), 'GUARDIAN_BRANCH_RULES_PAGINATION_UNKNOWN');
  requireProof(commits.length > 0 &&
    commits.every((commit) => object(commit) && SHA.test(commit.sha)) &&
    new Set(commits.map((commit) => commit.sha)).size === commits.length &&
    commits[commits.length - 1].sha === headSha,
  'GUARDIAN_LAST_PR_COMMIT_NOT_EXACT_HEAD');
  const contributors = new Set(commits.flatMap((commit) =>
    [commit.author?.id, commit.committer?.id].filter(positive)));
  requireProof(releasePolicy.reviewerIds.every((id) => !contributors.has(id)),
    'GUARDIAN_REVIEWER_IS_COMMIT_CONTRIBUTOR');
  validateTouchedFiles(files);
  branchRulesEvidence(rules.body, guardianAppId, releasePolicy.minApprovals,
    expectedEvidence);
  await rulesetBypassEvidence(rules.body, installationToken);
  const approvedCount = reviewEvidence(reviews, releasePolicy, pr.author.id, headSha);

  const workflowProofs = [];
  for (const binding of releasePolicy.workflows) {
    const matching = releasePolicy.workflows.filter((x) => x.type === binding.type);
    requireProof(matching.length === 1, 'GUARDIAN_WORKFLOW_POLICY_AMBIGUOUS');
    const spec = expectedEvidence.filter((item) => item.type === binding.type);
    requireProof(spec.length === 1, 'GUARDIAN_EXPECTED_CHECK_POLICY_AMBIGUOUS');
    const policyChecks = snapshot.checkRuns.check_runs.filter((check) =>
      check.name === spec[0].checkName && check.app?.id === spec[0].issuerAppId &&
      check.head_sha === headSha && check.status === 'completed' &&
      check.conclusion === 'success');
    // A caller must supply the independently signed expected check mappings;
    // never infer them from a run's self-reported name.
    requireProof(policyChecks.length === 1,
      'GUARDIAN_WORKFLOW_EXPECTED_CHECK_MISSING');
    workflowProofs.push(await workflowJobProof({ token: installationToken,
      headSha, check: policyChecks[0], binding }));
  }
  return Object.freeze({ approvedCount, lastCommitSha: headSha,
    workflowProofs, rulesetBoundToGuardianApp: true,
    rulesetBypassActorsVerified: true,
    changedFileCount: files.length });
}

module.exports = { collectGuardianConclusiveProvenance, GuardianProvenanceError };
