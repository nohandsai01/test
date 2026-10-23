# Merge Gate independent Tests / CI: staging plan

Status: **STAGED SOURCE ONLY**. This Draft PR does not authorize tests,
activation, Merge, Deploy, payments, or launch.

| Role | Workflow file | Job check name | Evidence |
| --- | --- | --- | --- |
| Tests | `.github/workflows/merge-gate-tests.yml` | `NO HANDS Merge Gate / Tests` | Run the committed Node `test/*.test.cjs` suite; reject empty suite. |
| CI | `.github/workflows/merge-gate-ci.yml` | `NO HANDS Merge Gate / CI` | Check JS/CJS/MJS syntax in `test/` and `src/`; reject empty inputs. |

Both workflows trigger on `push` changing `src/**`, `test/**`, or `docs/**`.
They have different workflow IDs and check names. Their issuer is normally
GitHub Actions (the same App ID for both), which must differ from Guardian's
independently hosted App ID. Action references are immutable, checkout binds
to the triggering SHA, permissions are read-only, and no secrets are used.

This delivery modifies only workflow files and this note, so the `push.paths`
filter does **not** run either workflow on the staging push. There is no
`workflow_dispatch` or `pull_request` trigger. `main` currently lacks `test/`:
later eligible events fail closed until test source is independently approved
and committed. **No green test or CI result is asserted here.**

**Required-check caveat:** GitHub leaves path-filtered required checks Pending
for skipped events. These jobs must never be marked required for PRs outside
the Guardian's eligible `src/`, `test/`, `docs/` scope.

## Separate owner-authorized activation gate

1. Independently review both workflow sources and eventual source/test coverage;
   resolve findings before any merge to the trusted default branch.
2. After authorized merge, collect **actual GitHub** workflow IDs, check names,
   Actions issuer App ID, triggering exact SHA, `push` run IDs and associated
   job/check IDs. Never synthesize them or trust PR-authored evidence.
3. Independently bind and verify signed `tests` and `ci` expected mappings in
   Guardian; its App ID must differ from Actions. Check exact SHA consistency.
4. Only on new owner authorization, enable active main branch rules requiring
   all three precisely App-pinned checks (Tests, CI, Guardian) and independent
   human reviews with stale-review dismissal and last-push approval. Confirm
   that `bypass_actors` is observably `[]` with sufficient permissions.
5. Keep Feature OFF, Launch HOLD, Ruleset Disabled, no payments, no Merge,
   no Deploy, and no tests during this staging task.
