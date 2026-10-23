# Independent static CI contract (development only)

This isolated PR #9-based development batch adds a nonempty `npm run ci`
without duplicating the existing `node --test` cases. It is designed for the
separate, currently Draft PR #10 `NO HANDS Merge Gate / CI` workflow after a
separately approved integration of both source lines.

CI executes `src/merge-gate-ci-static.cjs` and fails closed if it cannot:

- enumerate committed source and tests, including both existing test files;
- find required Guardian and candidate modules as regular files;
- parse each tracked JavaScript file in `src/`, `test/`, and both candidate
  directories using the runner's Node syntax checker;
- resolve literal CommonJS imports to Node built-ins or repository files; or
- parse required project and candidate JSON files.

It checks static packaging and source integrity. It does **not** execute tests,
contact GitHub or Coinbase, verify operational signatures, or certify actual
Guardian identity and exact-head `push` evidence. Dynamic imports and
behavioral correctness are outside this static CI check and require the
separate Tests workflow, independent review, and live operational evidence.

`package.json` and `package-lock.json` are `human_review_paths` under
`nohands.yml`; do not apply or merge without a separately approved review.
No workflows, branch rules, source runtime logic, payment routes, or deployment
are enabled by this development batch.

Status: **LOCAL DEVELOPMENT ONLY / FEATURE OFF / LAUNCH HOLD**.
