# Merge Gate CI evidence candidate — NOT ACTIVATED

Status: `SOURCE_ONLY / FEATURE_OFF / LAUNCH_HOLD`. This directory is deliberately outside `.github/workflows/`; a `.yml.example` file is not a hosted workflow and cannot produce GitHub check evidence.

## Scope and exact identity

- Repository: `nohandsai01/test` only.
- Candidate branch: `feat/merge-gate-ci-candidate-20261022` (forked from protected `main` at `2791b7f7f4a0e6cdc5825804131cbbf6c1343341`).
- Artifact: `trusted-evidence.yml.example` with two distinct job/check names, both explicitly fail closed.
- Existing `nohands.yml` declares `required_evidence: [tests, ci]` but does not yet declare trusted hosted workflow mappings.
- The current `main` branch is protected, but required status-check contexts are not configured. This candidate does not change those settings.

## Proposed mapping — documentation only, NOT in nohands.yml

The Merge Gate parser expects one `key|checkName|workflowPath` string per required evidence key. **Only after** an independently approved workflow has actually been installed at the stated path and produces truthful hosted checks, a separately authorized policy change may add:

```yaml
trusted_evidence_workflows:
  - "tests|NO HANDS Merge Gate / tests|.github/workflows/nohands-merge-gate-evidence.yml"
  - "ci|NO HANDS Merge Gate / ci|.github/workflows/nohands-merge-gate-evidence.yml"
```

The two names are proposed identifiers, not observed GitHub checks. Do not list them as passing, add them to required branch checks, or treat them as trusted evidence yet.

## Activation gates (separate Founder approval required)

1. Approve the exact workflow source at an immutable commit and a real hosted issuer for BOTH `tests` and `ci`; replace the two `exit 1` guards with evidence-producing steps that actually execute their named checks.
2. Keep least-privilege GitHub Actions permissions; no secrets, deployment, `pull_request_target`, or automatic write privileges in untrusted PR code.
3. Approve the GitHub App installation and repository selection, validate the App identity/scopes, and establish authoritative last-push information.
4. Independently close the relevant PR #281 QA/Security/review blockers on the exact source head. An existing Draft/source-only PR is not a runtime approval.
5. Authorize a policy commit for `trusted_evidence_workflows` and separately configure required branch status checks after the real check names and issuers are verified.
6. Obtain authenticated successful check evidence for the exact relevant head, re-run preflight only after the above are satisfied, and require a separate explicit launch decision.

## Evidence accounting

| Item | State |
| --- | --- |
| Protected `main` branch | Confirmed in GitHub settings |
| Required status checks on `main` | Not configured |
| Hosted `tests` / `ci` runs from this candidate | NOT_STARTED |
| Authenticated last-push/check issuer | NOT_PROVEN |
| PR #281 independent gate closure | NOT_PROVEN |
| Merge Gate preflight PASS | NOT_CLAIMED |
| Merge / Deploy / Payment | NOT_AUTHORIZED |

Do not copy this candidate into `.github/workflows`, edit protected `main`, run a test/demo, open/merge a PR, deploy, or mutate production during this development-only batch.
