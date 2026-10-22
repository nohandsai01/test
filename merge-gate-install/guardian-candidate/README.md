# Guardian evidence adapter — source-only candidate

**SOURCE_ONLY / FEATURE_OFF / LAUNCH_HOLD.** This isolated component is stacked
after Draft PR #2. It does not install a GitHub workflow/App, issue a check,
change branch rules, merge, deploy, or handle payments.

`evidence-snapshot.cjs` exports `inspectEvidenceSnapshot(rawPolicy, rawSnapshot)`.
Inputs must be raw JSON bytes or strings; duplicate keys and oversized input
fail closed. The function checks a prospective `nohandsai01/test` PR to `main`
at an exact pinned SHA, and checks two distinct internal evidence types:
`tests` and `ci`. Each must match one declared check name, approved issuer App
ID, the PR SHA, completed status, and successful conclusion. Missing, duplicate
or incomplete check-run lists are rejected.

## Contract for the later external collector

Candidate `rawPolicy` shape (values are placeholders, **not** approved IDs):

```json
{
  "schemaVersion": 1,
  "repository": "nohandsai01/test",
  "targetBranch": "main",
  "headSha": "<40 lowercase hexadecimal characters>",
  "evidence": [
    {"type":"tests", "checkName":"<approved name>", "issuerAppId":0},
    {"type":"ci", "checkName":"<approved name>", "issuerAppId":0}
  ]
}
```

IDs of `0` intentionally **cannot** pass. A separately governed Guardian
service must provide actual independently approved IDs, not accept values from
a PR author. A `rawSnapshot` is a normalized subset of GitHub's pull-request
and check-runs REST responses, with exact top-level keys `repository`,
`pullRequest`, `checkRuns`:

```json
{
  "repository":"nohandsai01/test",
  "pullRequest":{
    "number":2,
    "state":"open",
    "base":{"ref":"main","repo":{"full_name":"nohandsai01/test"}},
    "head":{"sha":"<exact head SHA>","repo":{"full_name":"nohandsai01/test"}}
  },
  "checkRuns":{"total_count":0,"check_runs":[]}
}
```

This illustrates a *future direct PR to main*. Draft PR #2 is actually stacked
against the post-QA feature branch and is not claimed eligible.

## Non-negotiable missing authority

Even when every field matches, output remains `trusted=false`,
`activationAllowed=false`, `hostedCheckEvidence=NOT_VERIFIED` and
`authoritativeRequiredCheck=NOT_ISSUED`. The only possible positive source
label is `SNAPSHOT_SHAPE_MATCH_ONLY`, not `PASS`.

Before any active GitHub App integration, separately prove:

1. Independent immutable policy source and authenticated App installation;
2. fresh direct GitHub API reads, complete pagination, and exact-head re-read;
3. check-run origin, workflow/run association, last-push and review provenance
   (matching only the App ID is insufficient);
4. protected-branch ruleset binding the single
   `NO HANDS Merge Gate Required Check` to the expected dedicated Guardian App;
5. separate Founder authorization to install, activate, merge, or deploy.

The `success` check here is deliberately stricter than GitHub's general
required-status-check acceptance of neutral/skipped outcomes.

Official references:

- https://docs.github.com/en/rest/checks/runs
- https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

No tests, QA, demo, hosted CI, deployment, or real payment is performed in
this delivery batch.
