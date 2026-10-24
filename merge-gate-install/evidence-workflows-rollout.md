# Merge Gate independent Tests / CI: staging plan

Status: **STAGED SOURCE ONLY**. This Draft PR does not authorize tests,
activation, Merge, Deploy, payments, or launch.

| Role | Workflow file | Job check name | Evidence |
| --- | --- | --- | --- |
| Tests | `.github/workflows/merge-gate-tests.yml` | `NO HANDS Merge Gate / Tests` | Run all committed nested `*.test.cjs`, `*.test.js`, `*.test.mjs` files; reject empty or unenumerable suite. |
| CI | `.github/workflows/merge-gate-ci.yml` | `NO HANDS Merge Gate / CI` | Check JS/CJS/MJS syntax with complete enumeration **and** execute an explicitly committed project `npm run ci`; reject missing inputs, lockfile, or CI command. |

Both workflows trigger on `push` changing `src/**`, `test/**`, `docs/**`,
`merge-gate-install/**`, either root package file, `nohands.yml`, or either
Merge Gate Tests/CI workflow file. This includes policy and workflow edits so
that their corresponding source evidence cannot silently remain stale.
This remains the **only** event accepted as Guardian's signed `event: push`
evidence. A `pull_request` fallback covers **all PRs targeting `main`**,
including eligible-only fork PRs and protected-only PRs, without path filters.
Its `edited` event also covers retargeting an existing PR to `main` without
new commits. PR-event jobs run only for non-Draft PRs; a separate eligible-root
`push` on an in-repository branch may still run even if its PR is Draft.
Same-repository eligible changes can produce both events. Only verified,
exact-head signed `push` evidence qualifies for Guardian; PR-event checks and
skipped jobs are never substitutes. Guardian independently rejects protected
changes, regardless of the displayed GitHub check conclusion.
They have different workflow IDs and check names. Their issuer is normally
GitHub Actions (the same App ID for both), which must differ from Guardian's
independently hosted App ID. Action references are immutable, checkout binds
to the triggering SHA (for PR fallback, the PR head SHA), permissions are
read-only, and no secrets are used.

PR #10's original isolated Draft source did not cause a qualifying `push`
run. In the combined PR #9/#10/#11 integration candidate, the broadened
`push.paths` **will match** a push of the integration branch. A push is not
authorized by this document, and can run real Tests and CI even while a PR
remains Draft. A Draft `pull_request` fallback job is skipped, and its skipped
conclusion is not Guardian evidence. Do not confuse that skipped fallback
with the independent `push` run.
There is no `workflow_dispatch` event. `main` currently lacks `test/`,
`package.json`, and `package-lock.json`: later eligible events fail closed
until test source **and** an independently reviewed nonempty `scripts.ci`
contract are committed. Do not make `scripts.ci` silently pass or rerun the
same test suite in place of a meaningful separate CI task.
**No green test or CI result is asserted here.**

**Required-check caveat:** GitHub leaves workflow-level path-filtered
required checks Pending when skipped; job-level Draft skips can display Success
for branch protection but are **not** valid Guardian evidence. The unfiltered
PR fallback provides check contexts for every PR path class targeting `main`,
but fork PR runs may await maintainer approval or be unavailable by repository
policy. Guardian independently rejects diffs outside `src/`, `test/`, `docs/`.
The Ruleset applies to all PRs targeting `main`, not conditionally by file.
Before activation, separately verify that each expected non-Draft PR class
produces the intended check context and that exact-head signed push evidence
remains mandatory for Guardian PASS. Treat missing, stale, or skipped checks as
HOLD, never as successful source evidence.

## Merge Queue exclusion (current staging)

No `merge_group` event is configured. **GitHub Merge Queue is not supported by
this staged workflow and is outside this activation scope.** Do not enable
Merge Queue while expecting these two checks to provide queue-head evidence.
A future separately authorized change must design and verify queue-specific
triggering, checkout SHA binding, check identity, and Guardian attestation;
`pull_request` results must never be treated as signed `push` or queue evidence.

## Separate owner-authorized activation gate

1. Independently review both workflow sources and eventual source/test coverage;
   resolve findings before any merge to the trusted default branch.
2. After authorized merge, collect **actual GitHub** workflow IDs, check names,
   Actions issuer App ID, triggering exact SHA, eligible `push` run IDs and
   associated job/check IDs. Separately inspect fallback PR-event check
   contexts; they are NOT substitutes for signed Guardian push evidence.
   Never synthesize IDs or trust PR-authored evidence.
3. Independently bind and verify signed `tests` and `ci` expected mappings in
   Guardian; its App ID must differ from Actions. Check exact SHA consistency.
4. Only on new owner authorization, enable active main branch rules requiring
   all three precisely App-pinned checks (Tests, CI, Guardian) and independent
   human reviews with stale-review dismissal and last-push approval. Confirm
   that `bypass_actors` is observably `[]` with sufficient permissions.
5. Keep Feature OFF, Launch HOLD, Ruleset Disabled, no payments, no Merge,
   no Deploy. Authorized integration verification is a separate, explicit
   gate; this document does not authorize a push or tests.
