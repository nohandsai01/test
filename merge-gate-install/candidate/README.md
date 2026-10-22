# Merge Gate CI evidence candidate — NOT ACTIVATED

Status: `SOURCE_ONLY / FEATURE_OFF / LAUNCH_HOLD`. This directory is deliberately outside `.github/workflows/`; a `.yml.example` file is not a hosted workflow and cannot produce GitHub check evidence.

## Scope and exact identity

- Repository: `nohandsai01/test` only.
- Candidate source scope: `feat/merge-gate-postqa-20261022` (based on `main` at `2791b7f7f4a0e6cdc5825804131cbbf6c1343341`). This source-declared branch is not authenticated branch provenance.
- Artifact: `trusted-evidence.yml.example` has two deliberately failing example jobs; neither is a trusted check issuer.
- Existing `nohands.yml` declares `required_evidence: [tests, ci]` but does not yet declare trusted hosted workflow mappings.
- The current `main` branch is protected, but required status-check contexts are not configured. This candidate does not change those settings.

## Required-check identity — documentation only, NOT configured

`tests` and `ci` are two *internal evidence types*, not two independently trusted GitHub required checks. The sole eventual authoritative required context is `NO HANDS Merge Gate Required Check`, issued by the separately authenticated Guardian App. The candidate workflow cannot publish that context. Mapping internal evidence to proven workflows, or registering the App check as required, needs separate approval and exact-head evidence.

The source-only candidate may run developer QA, but neither its results nor self-declared workflow names can establish an App-authenticated check, trusted anchor, or production policy authority.

## Activation gates (separate Founder approval required)

1. Independently approve the actual evidence producers for `tests` and `ci`; this inert example's two `exit 1` guards must remain unchanged in the source-only stage.
2. Keep least-privilege GitHub Actions permissions; no secrets, deployment, `pull_request_target`, or automatic write privileges in untrusted PR code.
3. Approve the GitHub App installation and repository selection, validate the App identity/scopes, and establish authoritative last-push information.
4. Independently close the relevant PR #281 QA/Security/review blockers on the exact source head. An existing Draft/source-only PR is not a runtime approval.
5. Authorize trusted evidence mappings and the single App-issued required context only after their names, issuers and exact-head behavior have been independently verified.
6. Obtain authenticated successful check evidence for the exact relevant head, re-run preflight only after the above are satisfied, and require a separate explicit launch decision.

## Evidence accounting

| Item | State |
| --- | --- |
| Protected `main` branch | Confirmed in GitHub settings |
| Required status checks on `main` | Not configured |
| Hosted *trusted* `tests` / `ci` evidence from this candidate | NOT_VERIFIED; source-only developer QA is non-authoritative |
| Authenticated last-push/check issuer | NOT_PROVEN |
| PR #281 independent gate closure | NOT_PROVEN |
| Merge Gate preflight PASS | NOT_CLAIMED |
| Merge / Deploy / Payment | NOT_AUTHORIZED |

Do not copy this inert example into `.github/workflows`, edit protected `main`, merge/deploy, run live payment/demo, or mutate production during this development-only batch. Bounded *source-only* developer QA is permitted and does not alter the activation hold.
