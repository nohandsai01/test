# Merge Gate independent Tests / CI: staging plan

Status: **STAGED SOURCE ONLY**. This Draft PR does not authorize tests,
activation, Merge, Deploy, payments, or launch.

| Role | Workflow file | Job check name | Evidence |
| --- | --- | --- | --- |
| Tests | `.github/workflows/merge-gate-tests.yml` | `NO HANDS Merge Gate / Tests` | Run all committed nested `*.test.cjs`, `*.test.js`, `*.test.mjs` files; reject empty or unenumerable suite. |
| CI | `.github/workflows/merge-gate-ci.yml` | `NO HANDS Merge Gate / CI` | Check JS/CJS/MJS syntax with complete enumeration **and** execute an explicitly committed project `npm run ci`; reject missing inputs, lockfile, or CI command. |

Both workflows trigger on `push` changing `src/**`, `test/**`, or `docs/**`.
This remains the **only** event accepted as Guardian's signed `event: push`
evidence. A `pull_request` fallback (for `main`, with `paths-ignore` for those
three eligible roots) supplies ordinary required-check contexts for PRs that
otherwise cannot produce push evidence. The fallback runs only when the PR is
non-Draft. If a PR combines eligible and protected files, both events may run;
Guardian must still reject protected changes, independent of any green job.
They have different workflow IDs and check names. Their issuer is normally
GitHub Actions (the same App ID for both), which must differ from Guardian's
independently hosted App ID. Action references are immutable, checkout binds
to the triggering SHA (for PR fallback, the PR head SHA), permissions are
read-only, and no secrets are used.

This delivery modifies only workflow files and this note, so the `push.paths`
filter does **not** run either workflow on the staging push. PR #10 remains
Draft, so any fallback job on its `synchronize` event is **skipped without
running tests or CI**, and its skipped conclusion is not Guardian evidence.
There is no `workflow_dispatch` event. `main` currently lacks `test/`,
`package.json`, and `package-lock.json`: later eligible events fail closed
until test source **and** an independently reviewed nonempty `scripts.ci`
contract are committed. Do not make `scripts.ci` silently pass or rerun the
same test suite in place of a meaningful separate CI task.
**No green test or CI result is asserted here.**

**Required-check caveat:** GitHub leaves path-filtered required checks Pending
for skipped events. The PR fallback addresses protected-only changes but is
not sufficient to authorize them: Guardian independently rejects any diff
outside `src/`, `test/`, `docs/`, and a Draft skipped check is never proof.
The Ruleset applies to all PRs targeting `main`, not conditionally by file.
Before activation, separately verify that each expected non-Draft PR class
produces the intended check context and that exact-head signed push evidence
remains mandatory for Guardian PASS. Treat missing, stale, or skipped checks as
HOLD, never as successful source evidence.

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
   no Deploy, and no tests during this staging task.
