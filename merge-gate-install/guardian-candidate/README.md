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

## Next source-only development batch: authenticated reader + signed policy

The following three modules are stacked after the original evidence snapshot
adapter. They are **not** a production Guardian installation:

- `signed-policy.cjs` verifies an Ed25519 signature over raw policy bytes. The
  envelope has exactly `schemaVersion`, `algorithm`, `payloadBase64`, and
  `signatureBase64`. The signed payload has `schemaVersion`, `issuedAt`,
  `expiresAt`, and `evidencePolicy` (the exact policy shape above). Signatures
  must be canonical base64 and the signed approval must expire within 24 hours.
  The public key is injected by a separate trusted runtime, never read from
  this repository or the incoming PR.
- `github-rest-collector.cjs` uses **HTTPS GET only** to fixed
  `api.github.com` REST endpoints with a GitHub App **installation access
  token** supplied by the host. It checks installation repository scope,
  fetches the PR twice, fetches the check-suite count to reject GitHub's
  1000-suite truncation boundary, enumerates every page of check runs with
  `filter=all`, rejects missing/duplicate records, and re-reads the first check
  page to detect some concurrent changes. There is no anonymous/PAT fallback,
  arbitrary URL, redirect follow, mutation, or token logging. This is **not an
  atomic snapshot** and does not establish last-push or reviewer provenance.
- `read-and-evaluate.cjs` verifies the signed policy first, then makes the
  authenticated REST reads, and only then calls `inspectEvidenceSnapshot`.
  Its output **always remains `SOURCE_ONLY_HOLD`, `trusted:false`,
  `activationAllowed:false`, and `authoritativeRequiredCheck:NOT_ISSUED`**.

### Runtime boundary

The host integration must supply these fields, outside PR-controlled content:

```js
const { readAndEvaluateGuardianCandidate } = require('./read-and-evaluate.cjs');

const result = await readAndEvaluateGuardianCandidate({
  pullNumber: approvedPullNumber,
  signedPolicyEnvelope: independentlyIssuedEnvelopeBytes,
  trustedPolicyPublicKeyPem: protectedHostTrustAnchor,
  githubAppInstallationToken: hostMintedReadOnlyInstallationToken,
});
// result.trusted === false; result.activationAllowed === false
```

This snippet defines a future host contract, **not** an executable runbook.
No private key, token, key material, or approved App ID is included here.
The source cannot attest that the host's public key is independently managed,
that an installation token came from the intended App, or that the target's
branch protection is configured. Those are external activation gates.

The collector uses the documented `GET /installation/repositories`,
`GET /repos/{owner}/{repo}/pulls/{pull_number}`,
`GET /repos/{owner}/{repo}/commits/{ref}/check-suites`, and
`GET /repos/{owner}/{repo}/commits/{ref}/check-runs` endpoints. The latter
uses `filter=all`, not the default `latest`. The code rejects counts beyond
its bounded collection capacity, rather than treating a partial result as
complete. It uses the pinned REST API version `2022-11-28`.

## Next source-only development batch: App host, onboarding and FAILURE check

The following modules extend PR #4 but **do not install, start, activate or
deploy** a Guardian GitHub App:

| File | Source-only implementation | Critical limitation |
| --- | --- | --- |
| `github-app-identity.cjs` | Signs short-lived RS256 App JWTs; cross-checks GitHub `/user`, App installation, repository installation and repository identity; exchanges a verified installation ID for a repository-ID-scoped token; provides a **failure-only** `POST /check-runs` function | Requires separately protected App ID/RSA private key, OAuth session-bound owner token and numeric GitHub owner/repository IDs; no `success` writer |
| `guardian-webhook-runtime.cjs` | Validates webhook HMAC, event and installation; checks durable verified installation binding; reserves the delivery across replicas before any outbound request; fetches an independently signed policy and can publish a **failure** check | Host must supply verified binding, independent policy authority and durable replay store; default OFF |
| `github-app-onboarding.cjs` | Issues a 256-bit state-bound GitHub installation link; consumes a durable one-time intent; calls GitHub REST to verify the owner, App installation and repository before storing a verified binding | Redirect `installation_id` remains untrusted until API verification. OAuth token-to-owner-session binding must occur in the protected host |
| `guardian-d1-stores.cjs` / `guardian-d1-schema.sql` | D1-backed single-use setup intent, immutable installation-binding reservation, permanent webhook-delivery replay tombstones | SQL schema must be applied to an isolated owner-managed D1 separately; no migration or provisioning is performed here |
| `independent-policy-source.cjs` | Fetches a bounded policy envelope from a fixed HTTPS host and verifies Ed25519 signature against a pinned SPKI fingerprint and exact PR head | Operational separation of the signing authority must be evidenced externally; source cannot certify it |
| `guardian-http-server.cjs` | Creates an HTTP `/github/webhook` handler and `/healthz` entry point with body and timeout bounds | `createGuardianHttpServer` does **not** call `.listen()`; needs owner-controlled host, TLS termination and operational controls |

### External runtime integration contract — inert by default

```js
const { createGuardianHttpServer } = require('./guardian-http-server.cjs');
const { createGuardianD1Stores } = require('./guardian-d1-stores.cjs');
const stores = createGuardianD1Stores(protectedIsolatedGuardianD1Binding);
const server = createGuardianHttpServer({ host: {
  webhookSecret: protectedWebhookSecret,
  trustedInstallationId: ownerApprovedInstallationId,
  guardianAppId: ownerApprovedGuardianAppId,
  expectedOwnerAccountId: pinnedGitHubOwnerNumericId,
  expectedRepositoryId: pinnedGitHubRepositoryNumericId,
  githubAppPrivateKeyPem: protectedAppRsaKey,
  installationStore: stores.installationStore,
  deliveryStore: stores.deliveryStore,
  policyAuthority: {
    hostname: ownerConfiguredIndependentPolicyHostname,
    publicKeyPem: protectedIndependentEd25519PublicKey,
    pinnedSpkiSha256: pinnedIndependentEd25519SpkiFingerprint,
  },
  enableFailureCheckWrites: false,
  founderAuthorizedFailureOnly: null,
} });
// No .listen(): this is NOT a running service or activation instruction.
```

Both opt-ins (`enableFailureCheckWrites === true` and an explicit host-owned
`founderAuthorizedFailureOnly === 'EXPLICIT_FAILURE_ONLY'`) plus verified
HMAC, GitHub-API-verified installation binding, durable replay reservation and installation token
are required before source code can even *attempt* a failure check. The token
minting request scopes access to `nohandsai01/test` and `checks:write` plus
`pull_requests:read`. In no configuration does this code issue `success`,
`neutral`, or `skipped` as an authoritative required check result.

`/healthz` is not a readiness/authorization probe. A valid setup callback is
not proof that an installer has permission to bind the App to an account.
Neither a successful signed policy shape match nor a successful failure-only
check proves last-push timing, reviewer provenance, branch protection binding,
or an owner-authorized product launch. The policy source is external, not a
PR-authored configuration file.

### G6 integration contract — three protections in one batch

1. **GitHub App identity binding.** The setup callback consumes a 10-minute,
   single-use owner-session state, then reads GitHub's authenticated `/user`,
   `/app/installations/{installation_id}`,
   `/repos/nohandsai01/test/installation` and
   `/repos/nohandsai01/test` endpoints. The resulting binding contains the
   numeric App, installation, owner and repository IDs. A GitHub App user
   access token must first be cryptographically bound to the same verified
   owner browser session by a separately operated OAuth host. This source
   implements API cross-checks, **not** that host's OAuth callback.
2. **Independent permission decision.** The delivery host only fetches a
   signed policy from an owner-pinned HTTPS hostname with an independently
   pinned Ed25519 SPKI SHA-256 fingerprint. The signature and exact head are
   verified before the evidence evaluator runs. The protected host must
   demonstrate separate administrators and signing-key custody outside this
   repository. An independently signed policy is still **not** a merge or
   launch authorization. No PR-authored policy can override the host.
3. **Persistent replay prevention.** `createGuardianD1Stores(db)` supplies
   atomic D1 `INSERT OR IGNORE` / guarded `UPDATE` operations backed by
   primary keys. Setup state is consumed once; one installation binding is
   reserved once; every webhook delivery ID receives a permanent SHA-256
   tombstone before external calls. Database errors, duplicate reservations
   and uncertain writes fail closed. `guardian-d1-schema.sql` is a proposed
   schema only: the source does not create a Cloudflare resource, run a
   migration, erase tombstones, or provide in-memory replay fallback.

The owner host must separately create the isolated D1, apply and review the
schema, protect credentials, bind OAuth user tokens to sessions, attest policy
authority independence and provide a revocation/rebinding process. The
verified binding is not an invitation to turn the feature on. D1 is **not**
configured, and this batch does not call `.listen()`, perform live payments,
submit installation requests or run tests. The only possible host-written
Check Run remains a Founder-opted-in **failure**; there is no PASS writer.

### G7 — GitHub App OAuth bridge + exact-PR policy scope

The G7 module `guardian-owner-oauth.cjs` connects the two **different**
GitHub redirects. It does not start a listener or install an App:

1. The trusted host starts with `beginGuardianInstallation(...)` and retains
   `stateForHostCookie` in a **Secure, HttpOnly, SameSite=Lax** first-party
   cookie alongside its own unguessable browser session. GitHub does **not**
   promise to echo install-link `state` to the **Setup URL**. Do not trust
   callback query parameters as the original installation state.
2. The protected **Setup URL** handler reads that cookie and session, then
   calls `beginGuardianSetupOAuth(...)` with the untrusted GitHub
   `installation_id`/`setup_action`. The D1 `oauthStore` atomically persists
   a separate ten-minute OAuth state and PKCE verifier bound to the same
   browser session and installation-state hashes. The browser is redirected
   to the fixed GitHub OAuth authorization URL.
3. The separate **OAuth Callback URL** handler calls
   `completeGuardianSetupOAuth(...)` with returned `state`/`code` and the
   original protected cookies. D1 consumes the OAuth state **before** the
   HTTPS authorization-code exchange with PKCE. The GitHub `ghu_` user token
   is held only in memory for the owner `/user` and App/repository API
   cross-checks; the original install intent is consumed separately before
   writing an inert verified binding. Duplicate, mismatched, expired, or
   uncertain state transitions HOLD. No token is written to D1.

Source-only host integration sketch:

```js
const { beginGuardianSetupOAuth, completeGuardianSetupOAuth } =
  require('./guardian-owner-oauth.cjs');
const stores = createGuardianD1Stores(protectedGuardianD1Binding);

// Setup URL, using a protected same-origin cookie and protected session:
const authorization = await beginGuardianSetupOAuth({
  installationState: installationStateFromHostCookie,
  installationId: untrustedSetupInstallationId,
  setupAction: untrustedSetupAction,
  browserSessionId: protectedBrowserSessionId,
  clientId: protectedClientId, redirectUri: pinnedHttpsOAuthCallback,
  oauthStore: stores.oauthStore,
});

// OAuth Callback URL, using those SAME protected cookies/session:
const outcome = await completeGuardianSetupOAuth({
  state: oauthQueryState, code: oauthQueryCode,
  installationState: installationStateFromHostCookie,
  browserSessionId: protectedBrowserSessionId,
  oauthStore: stores.oauthStore, intentStore: stores.intentStore,
  installationStore: stores.installationStore,
  clientId: protectedClientId, clientSecret: protectedClientSecret,
  redirectUri: pinnedHttpsOAuthCallback, appId: protectedNumericAppId,
  privateKeyPem: protectedAppRsaKey,
  expectedOwnerAccountId: protectedNumericOwnerId,
});
// outcome.activated is always false, including when an owner is verified.
```

The host still needs to implement session/cookie issuance, HTTPS routes,
CSRF and rate limiting, and register a real GitHub App. This source assumes
the **Setup URL then OAuth** mode; GitHub's “Request user authorization on
install” option instead uses the OAuth callback and cannot simultaneously
configure a Setup URL. No App or OAuth credentials are provided here.

G7 also closes a separate policy scope gap: the independent authority's
Ed25519-signed **payload** must now contain `schemaVersion: 2` and
`pullNumber: <exact numeric PR>` alongside `issuedAt`, `expiresAt`, and the
existing v1 `evidencePolicy`. Both the remote policy fetch and the evidence
reader require the matching PR number. A signature only bound to a shared
Commit SHA (legacy v1), or signed for a different PR, cannot be used on that
runtime path. This still cannot establish independent signer custody or
release authority without separate operational evidence.

Official OAuth references:

- https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
- https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url

Source-only integration still needs the independently operated service host,
registered GitHub App identity, verified installer account binding, durable
data store, rate limits, observability, approved keys, active branch ruleset,
and a separate final acceptance gate. There is no attempt to provision any of
those resources in this batch.

### G8 — protected owner HTTP onboarding adapter (still inert)

`guardian-owner-http.cjs` supplies the missing HTTP boundary between the G7
OAuth/PKCE bridge and an independently authenticated owner host. The existing
`createGuardianHttpServer` attaches it **only** when
`host.enableOwnerOnboardingRoutes === true` and a complete
`host.ownerOnboarding` configuration is injected. Merely importing modules or
creating the HTTP server **never calls `.listen()`**, registers an App, or
enables FAILURE checks. This source does not create an owner login system.

| Route | Request | Host protections and result |
| --- | --- | --- |
| `/guardian/install/start` | `POST`, zero-length body | Authenticated and pinned numeric owner identity, `Origin`, protected host CSRF validator and rate limiter; stores an install intent, then sets the `__Host-guardian_install_state` first-party cookie and issues a 303 redirect to the fixed GitHub installation URL |
| `/guardian/install/setup` | `GET` with GitHub `installation_id`; optional `setup_action` | Same verified host session and protected cookie, strict single-value query parsing and rate limit; reserves durable OAuth state/PKCE, then issues a 302 redirect to GitHub OAuth; the claimed installation ID is **not trusted** |
| `/guardian/install/oauth/callback` | `GET` with OAuth `code` and `state` | Same session/cookie and rate limit, consumes state once before GitHub token exchange, verifies account/installation/repository through GitHub REST, clears the temporary cookie and reports only `INSTALLATION_VERIFIED_NOT_ACTIVATED` or HOLD |

The owner host must supply `authenticateOwnerRequest(req)` returning a
**server-verified** `{sessionId, ownerAccountId}`, `verifyCsrf(...)`, and a
**durable** `rateLimiter.allow(...)`, together with exact pinned origin,
callback, App identity, keys and the three previously defined D1 stores. It
must not treat a cookie or inbound query alone as a login. If any dependency
is missing, setup routing fails closed; no in-memory fallback exists. The
public origin must be HTTPS with no arbitrary path, the callback URI must be
that origin plus `/guardian/install/oauth/callback`, and a trusted external
TLS terminator must constrain Host headers. `X-Forwarded-*` does not create
trust by itself. The state cookie is `Secure; HttpOnly; SameSite=Lax; Path=/`,
with a ten-minute maximum age and no `Domain` attribute.

When registering the GitHub App separately, the proposed Setup URL is the
exact owner HTTPS origin plus `/guardian/install/setup`, while the OAuth
authorization callback is `/guardian/install/oauth/callback`. GitHub's
Setup URL documentation only guarantees `installation_id`; if
`setup_action` is missing, this router labels the intent `install` solely
for local correlation, **not** authorization. GitHub REST cross-checking
remains mandatory. A hostile duplicate, unexpected query, cross-origin
start, stale state, failed CSRF/rate limit, unexpected redirect target, or
ambiguous cookie results in HOLD.

This delivery provides **source code**, not a live host. The HTTP adapter
cannot attest that the host's owner authentication, TLS, CSRF token custody,
rate limiting or D1 migration actually exists. It has no success check writer
and cannot lift Feature OFF / Launch HOLD. No tests, QA, CI, App installation,
schema migration, deployment or activation are performed as part of G8.

Additional official references:

- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
- https://docs.github.com/en/rest/apps/apps
- https://docs.github.com/en/apps/sharing-github-apps/sharing-your-github-app
- https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url

### G9 — fresh installation-scope gate before Check Run egress (source-only)

A durable installation binding is historical evidence; it is **not** proof
that a GitHub App remains installed, unsuspended, or authorized for this
repository today. G9 introduces `revalidateCurrentInstallationScope(...)`
in `github-app-identity.cjs` and places it immediately before the existing
**FAILURE-only** `POST /check-runs` call in `guardian-webhook-runtime.cjs`.

- The host-authenticated App JWT re-reads the exact installation and the
  exact `nohandsai01/test` repository installation from fixed HTTPS GitHub
  REST endpoints; the short-lived scoped installation token independently
  re-reads numeric repository identity.
- Both installation records must match the pinned App ID, installation ID,
  numeric owner ID, owner login/type, selected repository scope, unsuspended
  state, required `checks:write` and `pull_requests:read` permissions, and
  `pull_request` subscription. The repository must match the pinned numeric
  repository ID and owner.
- Any GitHub 404/401, permission drift, API timeout, malformed response or
  mismatch returns `FRESH_INSTALLATION_SCOPE_UNVERIFIED` under HOLD **before**
  any Check Run write. The permanent webhook-delivery replay reservation has
  already occurred, so uncertain attempts require owner reconciliation.
- Revalidation is a point-in-time check, **not** an atomic GitHub authorization
  lease. Uninstall/revocation can race between the last GET and POST. The
  GitHub API remains the final enforcer; a separate revocation-event and
  owner-controlled rebinding workflow is still required before activation.

G9 does **not** add a success writer, change an environment flag, start a
listener, deploy, migrate D1, install an App, merge or execute any tests.
Feature OFF / Launch HOLD remain binding.

### G10 — complete SUCCESS / FAILURE source candidate (default OFF)

Founder authorization on 2026-10-23 covers **writing the inactive source**,
not activating the GitHub App, configuring branch protection or issuing a
positive live Check Run. This batch extends the *same* PR #9 source chain.
No new runtime is created, no `.listen()` occurs, no D1 migration is applied,
no workflow is installed, and no Check Run is submitted by the code delivery.

The independent signer can issue a **v3** policy payload (v1/v2 remain valid
only for fail-closed/failure-only inspection). v3 preserves the v2 signed
`pullNumber` and `evidencePolicy`, and additionally requires a signed
`releasePolicy` with exactly:

```json
{
  "schemaVersion": 1,
  "guardianAppId": 12345,
  "reviewerIds": [123456],
  "minApprovals": 1,
  "workflows": [
    {"type": "tests", "workflowId": 11111, "event": "push"},
    {"type": "ci", "workflowId": 22222, "event": "push"}
  ]
}
```

**All numbers above are invalid as operational approvals or host trust IDs**;
they are only syntax examples. The operator must independently pin the real
numeric identities and Ed25519 public-key fingerprint. A GitHub Check Run
cannot choose its own evidence issuer or reviewer allowlist.

`guardian-provenance.cjs` now checks the following on authenticated GitHub
REST reads, in addition to the original exact-head signed policy and complete
check-run pagination:

1. The PR is open, non-Draft, and has the signed exact head SHA. The final
   entry in the complete PR commit list matches the same SHA. The full changed
   file list is under `src/`, `test/` or `docs/` only; PR-supplied workflows,
   Guardian policy code and other protected files are not eligible to PASS.
2. A sufficient number of independently pinned reviewers have a **latest**
   `APPROVED` review on that exact SHA. The PR author and any GitHub-attributed
   commit contributor are excluded. Newer `CHANGES_REQUESTED` reviews HOLD.
3. For each signed `tests` and `ci` mapping, the successful Check Run has the
   exact name and issuer App ID; a GitHub Actions workflow run has the signed
   numeric workflow ID, same commit/check-suite, expected event and successful
   completion; a job in its latest run attempt has the exact check-run URL/ID,
   name, SHA and successful conclusion. Ambiguous or truncated lists HOLD.
4. GitHub's active branch rules for `main` must independently require all
   **three** uniquely pinned contexts: `NO HANDS Merge Gate Required Check`
   from the expected Guardian App, plus both signed `tests` and `ci` check names
   from their respective signed issuer App IDs. A missing, duplicate, or
   differently sourced underlying required check HOLDS even when its current
   GitHub Check Run is green. This makes GitHub's native required checks the
   continuing enforcement boundary if the same commit's CI is rerun after the
   Guardian issues a point-in-time `success`. The active PR review rule must independently
   require at least the signed minimum approvals, dismiss stale approvals on
   new pushes, and require approval by someone other than the last pusher.
   Missing rules, unpinned check names and malformed responses HOLD. The PR
   and Check Runs are re-read after provenance checks. **P2-01 bypass guard:**
   every active rule returned for `main` must identify its repository ruleset;
   the Guardian then reads each distinct `/rulesets/{id}` and requires an
   explicitly returned, empty `bypass_actors` array. Any configured bypass
   actor (including PR-only bypass), omitted/hidden array, ambiguous source,
   inaccessible ruleset or transport error HOLDS. The success summary refers
   only to this verified point-in-time state, not permanent non-bypassability.
   GitHub intentionally omits `bypass_actors` without ruleset **write** access:
   the currently scoped low-privilege App is therefore expected to HOLD even
   for an actually empty list. Do **not** silently grant Guardian repository
   administration/write access just to make it PASS; a separately reviewed
   least-privilege owner attestation design is an unresolved activation gate.
5. Immediately before egress, the host revalidates the installed, selected,
   unsuspended App/repository scope, now also with `actions:read` permission,
   and rechecks policy signature/expiry. A durable D1 reservation keyed by
   `(repository_id, pull_number, head_sha)` prevents conflicting conclusions
   from separate webhook delivery IDs. Uncertain writes require reconciliation.

Two mutually exclusive runtime modes are defined:

- Existing `enableFailureCheckWrites: true` plus
  `founderAuthorizedFailureOnly: 'EXPLICIT_FAILURE_ONLY'`: previous
  FAILURE-only behavior; **never** issues SUCCESS.
- New `enableFullCheckWrites: true` plus
  `founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES'`: can issue
  `success` **only** after every v3 provenance condition passes. Missing,
  transient or pending evidence leaves the required check absent (HOLD), so
  subsequent eligible review or workflow webhooks can retry the same SHA.
  A PR containing protected source changes is a terminal per-head violation
  and receives `failure`. It additionally needs `stores.conclusionStore` and an
  App installation with `actions:read`. Both modes OFF by default; enabling
  both is rejected **even if only one of the two grants is present**. Runtime
  activation requires a separate Founder decision.

Reviewers' commit-SHA binding and the final PR-commit SHA establish which
**content** was reviewed after the latest code change. They do not by
themselves prove a wall-clock GitHub push timestamp or prevent revocation
between final GET and POST. Operational event custody, independent signer
control, credential custody, D1 provisioning, GitHub App installation,
branch-rule setup, reviewer membership and separate release authorization
remain external acceptance gates.

The host must subscribe to authenticated `pull_request` and
`pull_request_review` events; `workflow_run.completed` is also understood
when GitHub supplies exactly one linked PR. `workflow_run` events with no
linked PR cannot safely identify a target and HOLD. In deployments where
GitHub Actions push runs have empty `pull_requests`, an independently trusted
reconciliation trigger is needed after CI completion. This source provides
`processGuardianReconciliation(...)` for that case, separately gated by
`enableOwnerReconciliation: true`,
`ownerReconciliationGrant: 'EXPLICIT_OWNER_RECONCILIATION'`, a protected
`authorizeReconciliation(...)` callback, and a durable
`reconciliationRateLimiter.allow(...)`. These are **all absent/OFF** in this
delivery. It generates an internal single-use delivery ID only after owner
authentication and independently verifies the signed PR/head via GitHub.
It does not expose a public reconcile route, infer a PR from a branch name,
schedule background polling, or create operator authentication.

Relevant GitHub endpoints: `/pulls/{n}/commits`, `/pulls/{n}/reviews`,
`/pulls/{n}/files`, `/actions/workflows/{id}/runs`,
`/actions/runs/{id}/jobs`, `/rules/branches/main`, `/rulesets/{id}`,
and `/check-runs`.

## Non-negotiable missing authority

In the current **default-OFF source delivery**, output remains
`activationAllowed=false` and no authoritative hosted Check Run is issued.
The G10 positive evidence label `EVIDENCE_CONCLUSIVE_CANDIDATE` is still
`trusted=false`, `authoritativeRequiredCheck=NOT_ISSUED` until the separately
authorized runtime actually publishes and receives a verified receipt.

Before any active GitHub App integration, separately prove:

1. Independent immutable policy source and authenticated App installation;
2. fresh direct GitHub API reads, complete pagination, and exact-head re-read;
3. check-run origin, workflow/run association, last-push and review provenance
   (matching only the App ID is insufficient);
4. protected-branch ruleset requiring all three distinct checks: the Guardian
   context pinned to its dedicated App, plus the signed Tests and CI contexts
   each pinned to its signed issuer App; GitHub must continue enforcing the
   underlying checks even after Guardian has written `success`;
5. separate Founder authorization to install, activate, merge, or deploy.

The `success` check here is deliberately stricter than GitHub's general
required-status-check acceptance of neutral/skipped outcomes.

Official references:

- https://docs.github.com/en/rest/checks/runs
- https://docs.github.com/en/rest/checks/suites
- https://docs.github.com/en/rest/apps/installations
- https://docs.github.com/en/rest/pulls/pulls
- https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
- https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

G10 source completion: five focused offline tests passed (5/5), with no
network or real Check Run writes. One existing candidate test in the earlier
combined run was blocked by this executor's read-only `/tmp` (`EROFS`), not by
a code assertion; it was not repeatedly rerun. No QA agent, hosted CI,
App installation, D1 migration, deployment, merge, or real payment was
performed in G10.

## Bounded operator Check triage — source-only, default HOLD

`guardian-conclusion-batch.cjs` exports
`reconcileGuardianConclusionBatch({ repositoryId, expectedAppId,
installationToken, conclusionStore, targets })`. The protected operator host
(not a public PR/webhook input) supplies a repository-scoped read token and the
verified D1 `conclusionStore.getReservation` adapter. `targets` contains 1–8
unique `{ pullNumber, headSha }` pairs. Caller-defined array iterators and
unstable lengths fail closed; enumeration uses a fixed index bound. Every identity is pinned before reads;
invalid or repeated targets reject the **entire batch without D1/GitHub I/O**.

The batch sequentially performs each existing authenticated, read-only single
Check reconciliation; one unavailable target does not conceal the observations
for another. The frozen report contains reason counts and strictly allowlisted,
non-secret per-target metadata. It never includes the installation token,
delivery digest, or raw remote payload. Missing Check does **not** imply a
failed Check POST or permit a second attempt. Even if GitHub shows an apparently
successful Check, every entry and the batch itself is `SOURCE_ONLY_HOLD` with
`automaticRetryAllowed=false`, `releaseAuthorized=false` and no Check writer.

This library is **not wired into a live HTTP route, scheduler, GitHub App or
production D1**. Its offline tests use a stubbed GitHub transport and a real
isolated SQLite D1 adapter. Operator authentication, live network proof,
independent runtime deployment, Check publication and release remain separate
Founder-gated requirements.

## Owner-authenticated operator HTTP reconciliation (source-only, default OFF)

The isolated route at POST /guardian/operator/check-reconcile is **not**
enabled by default. A separately authenticated Host may explicitly provide
enableReadOnlyOperatorRoutes=true and operatorReadOnly configuration to
createGuardianHttpServer(). Merely importing either module starts no listener
and exposes no public route.

Required protected operatorReadOnly contracts:

- publicOrigin must be the exact HTTPS origin pinned by the TLS terminator;
  ownerAccountId, repositoryId, guardianAppId are pinned numeric identities.
- authenticateOwnerRequest(req) supplies an independently authenticated owner
  session; verifyCsrf({sessionId,token}) and rateLimiter.allow(...) are mandatory.
  Never derive owner authority from a caller's JSON body, URL or Origin header.
- issueReadOnlyToken({sessionId,repositoryId,expectedAppId}) returns a
  repository-scoped read token with **exact** checks:read, pull_requests:read,
  metadata:read, and no extra permissions. The Host owns credential custody.
- conclusionStore.getReservation is the protected read-only D1 adapter.
  No reserveOnce, Check POST, counter reset or tombstone deletion is exposed.

Request: Content-Type application/json, exact HTTPS Origin and Host, owner CSRF
header, positive bounded Content-Length <= 4096, and exactly:
{"schemaVersion":1,"targets":[{"pullNumber":12,"headSha":"<40 lowercase hex>"}]}.
Targets must be unique, 1–8 pairs. Unexpected keys, duplicate JSON keys,
unknown origin, oversized/truncated body, missing owner authority, or
overscoped read token all HOLD. Transfer-Encoding and Content-Encoding are
rejected for this endpoint.

The read-only response is always SOURCE_ONLY_HOLD with
automaticRetryAllowed=false, releaseAuthorized=false,
authoritativeRequiredCheck=NOT_ISSUED. Only non-secret, allowlisted
observations may be returned. Missing or observed Checks never authorize
retry/merge/release. No raw token, delivery digest or remote payload is
returned. Any Host error, partial D1 read, or upstream GitHub error remains
a HOLD; operator triage cannot publish Checks.

Integration coverage uses a real loopback-only Node HTTP listener, an
in-memory SQLite instance with the actual Guardian schema, and synthetic
GitHub snapshots. It tests feature OFF, correct read-only observations,
multiple targets, owner/CSRF/rate failure, token privilege escalation,
malformed/duplicated JSON, and absence of live Check egress. This is not
Cloudflare D1 hosted E2E, App installation or production readiness.


### Hardened operator release boundary (same source-only milestone)

After each bounded read-only batch, the operator gateway independently
rebuilds the response from a strict allowlist of primitive fields; it does
not forward downstream objects or extra payload keys. It verifies each
observation's pull number, exact head, HOLD status, reason syntax, and optional
boolean/count/check metadata. Accessor-based output objects and malformed
claims fail closed. No provider secrets, raw response objects, check tokens,
or authority fields may be reflected.

The protected Host must supply a narrowly scoped checks:read token with
explicit expiresAt, repository ID, Guardian App ID and exactly read-only
checks, pull_requests, metadata permissions. The token must remain valid for
more than one minute when issued, and no more than one hour. It is snapshotted
before asynchronous reconciliation. A token expired during the read produces
a HOLD, never an issued Check or released observation.

The gateway independently reauthenticates the same owner session after the
batch completes, before returning any observations; revoked or changed
sessions reject the response. This is a source-only session freshness check,
not a proof of future revocation response by the Host. Client-disconnected
responses are not sent. A complete batch response still does not grant a
Check write, release, automatic retry or permission to clear D1 tombstones.

The local negative scenarios include hostile report fields and accessors,
mismatched target identities, session revocation during reads, expired and
overprivileged read tokens, and fail-closed sanitized HTTP responses.
No release authority is ever returned by this endpoint.


### Bounded operator recovery under stalled connections

The protected operator route now uses **one monotonic, end-to-end request
deadline** covering owner authentication, CSRF/rate checks, complete body,
short-lived read-token issuance, sequential D1/GitHub reconciliation, and the
final owner reauthentication. Default deadline is 8 seconds; the independent
Host may set requestTimeoutMs from 50 to 10000 milliseconds. Invalid budgets
fail at route construction, not at runtime. Every exceeded deadline returns
GUARDIAN_OPERATOR_READ_DEADLINE_EXCEEDED under SOURCE_ONLY_HOLD when the
client is still connected. No observation or retry/release authority is sent.

A cooperative Host dependency receives an AbortSignal; the signal is aborted
on a client disconnect or deadline. The HTTP request-body reader detaches all
stream listeners after completion/failure. A provider ignoring cancellation
may finish its **read** later, but the gateway never publishes that result or
sends another response. Production adapters must respect cancellation and
separately bound their own transport/read operations; a timeout wrapper
alone does not interrupt noncooperative network I/O.

Two independent local HTTP Host instances can inspect the same real temporary
SQLite reservation concurrently without changing the tombstone. Fault
injections exercise stalled owner auth, CSRF, rate limiting, token issuance,
GitHub reads, D1 reads, request-body upload, and late backend success.
All remain strictly operator-only and source-only; no Check POST, database
delete, deployed listener, GitHub App activation or production trust claim.


## Protected host bootstrap and runtime adapter (source-only, default OFF)

`guardian-protected-host.cjs` exports `createGuardianProtectedHost(config)`,
`bootstrapGuardianProtectedHost(config)` and `GuardianHostError`. It wraps the
**unmodified** `createGuardianHttpServer` handler with lifecycle, startup
probes and dependency-fault isolation. Webhook verification, Check publication,
operator reconciliation and owner onboarding remain in their existing modules.
Importing the module or calling `createGuardianProtectedHost` opens no port
and performs no D1 or GitHub I/O.

Configuration is an exact-key object; any unknown key (for example an injected
`deliveryStore` or `conclusionStore`) is `GUARDIAN_HOST_CONFIG_INVALID` with
only the field name in the error:

- `listenAddress` must be `127.0.0.1` or `::1`; public exposure and TLS
  termination are a separate owner-operated component. `port` 0–65535.
- `mode` is exactly one of `OFF`, `FAILURE_ONLY`, `FULL`. `FAILURE_ONLY`
  requires `modeGrant: 'EXPLICIT_FAILURE_ONLY'`, `FULL` requires
  `'EXPLICIT_FULL_CHECK_WRITES'`, and `OFF` must have no grant. A single field
  makes mixed write modes unrepresentable.
- Pinned positive integers `guardianAppId`, `trustedInstallationId`,
  `expectedOwnerAccountId`, `expectedRepositoryId`; `webhookSecret` (32–8192
  printable characters); `githubAppPrivateKeyPem` must parse as an RSA key of
  at least 2048 bits; `policyAuthority` must be an Ed25519 public key whose
  SPKI SHA-256 equals `pinnedSpkiSha256`.
- `d1Binding` is the raw isolated D1 binding. The host builds the D1 stores
  itself; there is no way to supply an in-memory store.
- Optional `operatorReadOnly` / `ownerOnboarding` contain only the
  owner-authentication callbacks and origins; the host injects the pinned
  identities and stores. The operator route receives a frozen view exposing
  **only** `conclusionStore.getReservation`.
- Optional `startupTimeoutMs` (100–30000, default 5000), `drainTimeoutMs`
  (0–30000, default 5000), `dependencyFaultThreshold` (1–20, default 3).

`start()` refuses to listen unless every probe passes within the startup
deadline: the required D1 tables are readable (`GUARDIAN_HOST_D1_SCHEMA_UNAVAILABLE`);
in a write mode, the D1 installation binding matches all four pinned IDs
(`GUARDIAN_HOST_INSTALLATION_BINDING_UNVERIFIED`), and the existing
`mintScopedInstallationToken` + `revalidateCurrentInstallationScope` pass
(`GUARDIAN_HOST_GITHUB_IDENTITY_UNVERIFIED`; the token is discarded). Any
failure leaves the host `FAILED` with no listener. `OFF` mode makes no GitHub
calls and every webhook still returns `FEATURE_OFF`.

While running, D1 store calls are counted. A D1 integrity fault (readback or
row mismatch, unverified result) latches `GUARDIAN_HOST_D1_INTEGRITY_HOLD`
immediately; `dependencyFaultThreshold` consecutive I/O faults latch
`GUARDIAN_HOST_D1_FAULT_HOLD`. A latched host answers every route with 503
`SOURCE_ONLY_HOLD` without touching D1 or GitHub. Healing D1 alone does not
release it; only a successful `start()`/`restart()` re-probe clears the latch.

`stop()` stops accepting connections, waits up to `drainTimeoutMs` for
in-flight requests and then closes remaining sockets (`abandonedInFlight`).
An abandoned handler may still complete its durable D1 reservation; because
both write modes share the `(repository_id, pull_number, head_sha)`
reservation and delivery IDs are permanent tombstones, neither `restart()`
nor a new process on the same D1 can publish a second Check for that head,
and an uncertain Check POST is never retried. `status()` always reports
`activationAllowed: false` and `releaseAuthority: 'NOT_ISSUED'` and never
includes secrets.

`test/guardian-protected-host.test.cjs` exercises a real loopback listener,
a temporary SQLite file with the actual schema as the isolated D1 binding,
ephemeral synthetic RSA/Ed25519 keys and stubbed GitHub transports with
`https.request` blocked. It covers configuration fail-closed cases, startup
probe failures and timeout, OFF mode, publish/stop, restart and cross-process
non-republication, two hosts racing on one D1, uncertain POST, D1 fault and
integrity latching, a GitHub scope fault, graceful and timed-out drain, the
read-only operator view and the lifecycle state machine. This is not
Cloudflare D1 hosted E2E, a GitHub App installation, signal handling or
process supervision, and it does not authorize activation.


## Final integration candidate (source-only, default OFF)

Branch `integrate/guardian-final-20261026` combines three writer heads
without rewriting them: the protected host (`8b68e883`, which already contains
the operator HTTP branch `c7c3e58e`) plus a merge of the Guardian core PR #12
head `8af6a851`. That head was not an ancestor of the operator branch, so its
batch hard-cap against hostile array iterators was missing; the merge is
conflict-free and leaves the batch report shape unchanged.

One host source change was needed: when the inner HTTP server rejects the
operator or onboarding configuration, the host now constructs each handler
alone on that error path and reports the section that was actually rejected
(`operatorReadOnly`, `ownerOnboarding` or `httpServer`). Previously a valid
operator section could be blamed for an invalid onboarding section.

`test/guardian-integrated-host-operator.test.cjs` runs the webhook runtime,
D1 durable reservation and read-only operator reconciliation together behind
one protected host on a loopback listener and a temporary SQLite file with the
real schema (GitHub stubbed, `https.request` blocked, synthetic keys):

- a failure-only Check recorded by a webhook is observed by the operator as
  `RECONCILIATION_CHECK_OBSERVED_ONLY`; the reservation row is byte-identical
  after operator queries and after `restart()`, and a later webhook for the
  same head stays `CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED`;
- through the host, the operator fails closed on a revoked owner session, a
  read token expiring mid-read, and stalled GitHub or token-issuer
  dependencies, without observations or D1 changes;
- a client disconnect and a host `stop()` (drain deadline) both propagate the
  operator `AbortSignal`, send no response and write nothing; `stop()`
  force-closes at its drain deadline instead of waiting for the operator's
  own deadline;
- a D1 outage hit by an operator read latches the host dependency HOLD, after
  which webhooks and operator calls are refused without D1/GitHub I/O;
- two integrated hosts on one D1 file publish one Check across four racing
  deliveries and return identical read-only observations;
- a static closure check over the committed candidate source: only
  `guardian-webhook-runtime.cjs` references a Check writer, reserves a
  conclusion or exposes owner reconciliation; the operator import chain cannot
  reach `github-app-identity.cjs`, the runtime or the D1 store module; the host
  always sets `enableOwnerReconciliation: false`.

Not covered: Cloudflare D1 hosted E2E, a real GitHub App installation, real
keys or Checks, TLS termination, signal handling/process supervision and any
production activation. Independent QA and security review remain required.

## G15 — isolated process supervision, bounded OS signal handling (source-only)

guardian-process-supervisor.cjs provides an **inert** process-manager adapter
for a protected Guardian host that already exposes start(), stop() and
status(). Importing or constructing it does not start a listener, install
OS signal handlers, register credentials, start a cloud App or change D1.

A separately owner-controlled process manager calls
createGuardianProcessSupervisor({host, onTerminal, signalSource?, stopDeadlineMs?})
with an independently configured createGuardianProtectedHost instance. The
owner explicitly calls await supervisor.start(). Only this explicit call
registers SIGTERM/SIGINT handlers, before asynchronous host start. No signal
is handled implicitly on import. The default signal source is Node's process,
but an injected emitter supports offline deterministic tests.

- Signals during startup queue a stop after startup settles. Simultaneous
  signals and a manual stop coalesce into **one** host.stop() attempt.
- Shutdown is bounded (default 15 seconds, configurable 50–30000 ms). The
  existing Protected Host performs its own graceful-drain/forced socket close;
  this supervisor only bounds the outer stop acknowledgement. A timed-out or
  failed stop returns FAILED and an immutable failure receipt. It must never
  claim the host stopped merely because the deadline elapsed.
- Startup errors attempt a bounded cleanup, including partial listeners. Any
  uncertainty is FAILED, never RUNNING. Signal listeners are removed after
  successful or failed termination; cleanup errors cannot be silently PASS.
- The owner-required synchronous onTerminal callback receives a single
  minimal frozen {state, reason, errorCode, hostStopped, activationAllowed,
  releaseAuthority} receipt. A missing or throwing callback is a configuration
  or terminal failure. **The external process manager** decides whether and
  how to kill/restart the process; this module never calls process.exit/kill,
  never restarts automatically, and never clears a D1 tombstone.
- status() and terminal receipts always declare activationAllowed=false
  and releaseAuthority=NOT_ISSUED. No raw Host keys, policy, tokens, request
  headers, D1 credentials or reservation contents appear in them.

Tests use synthetic signal emitters, bounded fake hosts, and a real loopback
listener. Child-process OS signal tests use only local Node processes,
no GitHub egress. These establish source/local OS-lifecycle semantics,
**not** live hosted D1, real Check App issuance, TLS/process manager deployment,
native GitHub Approval, or production readiness.

All prior Founder-only Merge, Deploy, App/Key, Ruleset, Check and production
actions remain prohibited. The feature is not integrated into a live launcher
and its activation remains HOLD.


### Explicit Protected Host / Supervisor assembly

The inert guardian-host-process-runner.cjs composes the existing strictly
validated Protected Host with guardian-process-supervisor.cjs. It requires
explicit protectedHostConfig and a synchronous owner onTerminal callback;
an injected signalSource and stopDeadlineMs are optional. Importing or
constructing the runner opens no port and subscribes to no OS signals.
Only an authorized external process manager may call runner.start().

The returned frozen facade exposes only start(), stop() and status(), not
protected configuration, D1 stores, tokens, keys, Check writers or the raw
Host instance. Status shows a strictly validated loopback address/port only
when RUNNING, never an externally routable URL, and always
releaseAuthority=NOT_ISSUED, activationAllowed=false. Tests instantiate a
real Protected Host in OFF mode with the actual SQLite schema and synthetic
RSA/Ed25519 key fixtures, read /healthz on loopback, then emit a synthetic
SIGTERM and verify the HTTP listener and process-manager signal handlers close.

This is source-only assembly, not production deployment, public network
exposure, provisioning, native GitHub approval or runtime activation.


## G16 — owner-controlled isolated child process manager (source-only)

guardian-local-process-controller.cjs implements an explicitly operated
local child-process lifecycle wrapper for the previously built Guardian
Host/Supervisor. Merely importing/constructing this module does not
spawn a child, configure a Host, create keys or contact GitHub/D1.

- Owner supplies an absolute, existing regular-file child entrypoint beneath
  a canonical pinned directory; symlinks and path changes before start are
  rejected. The module does not accept PR-supplied scripts or executable
  paths. Only the owner-controlled caller may invoke start().
- The child is started with Node's fixed process.execPath and shell=false,
  a minimal non-inherited environment (no app keys, GitHub tokens or secret
  refs passed via argv/environment) and an IPC-only lifecycle protocol.
- A valid READY message is a minimal source-only/HOLD receipt; it cannot
  enable real release authority. Unknown, duplicate, hostile or premature
  messages are protocol failures and never authorize any Check.
- The parent bounds readiness and graceful SIGTERM shutdown, escalating to
  SIGKILL **only for the ChildProcess instance it actually created** on
  timeout or a malicious child that ignores SIGTERM. No arbitrary PID, system
  process, Docker service or hosted runtime is addressed.
- Child exit is STOPPED only when a graceful stop was requested, a valid
  TERMINAL frame was observed and exit code was zero. Unexpected exit,
  startup failure, bad protocol, nonzero exit, forced shutdown, invalid
  terminal callback, or a stop before READY all remain FAILED.
- There is no auto-restart, remote registration, privilege elevation,
  production deployment, real Host configuration loading or real Check
  issuance. A separate owner process manager is responsible for immutable
  deployment images, key custody, and explicit staging activation.

Tests launch disposable local Node fixtures, establish loopback listeners,
exercise readiness/terminal IPC, SIGTERM escalation, child death, startup
timeout, rejected frames, duplicate events, and shutdown races. All statuses
and receipts stay non-authorizing. The tests do not use real keys or any
production D1/GitHub App. Completion is source-only until separately
authorized hosted E2E acceptance.


## G17 — protected Host child runtime and local durable terminal receipts

The child-side module guardian-child-runtime.cjs binds an OWNER-SUPPLIED
createRunner factory to an explicit ChildProcess IPC lifecycle. Import and
construction are inert: the external owner runtime decides which local
protected configuration factory is trusted. No Host configuration, App private
key, D1 binding or Check authority is accepted over the parent IPC channel.

The child starts the existing Protected Host process runner in its own
process, verifies RUNNING/HOLD status with a loopback-only GET /healthz
(including running=true, feature OFF_OR_SOURCE_ONLY and NOT_ISSUED) under
a bounded deadline, and only then emits the exact minimal READY frame. A
missing, malformed, stale or overlarge health result never enables READY.
An existing Supervisor SIGTERM/SIGINT stop causes the fixed TERMINAL frame
to be sent over the IPC channel before disconnection. No automatic restart,
public listener, process.exit or raw secret-bearing status is added.

The independent parent-side guardian-local-receipt-journal.cjs accepts
only terminal receipt primitives and writes an append-only JSONL line with
a random event ID and UTC timestamp. The caller pins an owner-only directory
and a tightly validated journal filename. The file uses O_APPEND, O_NOFOLLOW,
0600 permissions, bounded total size and synchronous fsync; symlinks, unsafe
directory permissions, unexpected receipt fields and storage uncertainty
fail closed. A journal failure makes the parent Controller return FAILED,
not a falsely clean STOPPED. The journal does not clear D1 reservations or
record tokens, private keys, raw errors, GitHub payloads or HTTP headers.

The new source-only child fixture builds an OFF-mode real Protected Host
with an isolated SQLite D1 schema and synthetic RSA/Ed25519 test keys
entirely within the child. Tests use a separately spawned Node process,
real IPC, loopback health, graceful signal shutdown and durable parent
journal across distinct child lifetimes. Negative scenarios cover premature
exit, falsified ready frames, corrupted health, health timeout, unsafe
receipts/filesystem permissions and failure to persist terminal evidence.
These proofs are LOCAL ONLY: they do not replace an approved protected
runtime image, hosted D1, GitHub App identity/issuer or production launch.


## G18 — local Guardian operator diagnostics and manual HOLD triage

guardian-local-diagnostics.cjs is a separate, read-only observation adapter
for an owned Guardian ChildProcess Controller and an append-only terminal
receipt journal. It is inert until inspect() is explicitly called. All
results keep status=SOURCE_ONLY_HOLD, liveness=NOT_PROVEN,
activationAllowed=false, releaseAuthority=NOT_ISSUED and
automaticRestartAllowed=false. PID presence or a previously clean STOPPED
record never constitutes proof that a process is alive or the hosted
Guardian Check issuer is safe.

The adapter pins an owner-only evidence directory and a fixed, allowlisted
journal filename; reads the journal with O_NOFOLLOW and bounded bytes;
verifies file ownership, size, permissions, inode/mtime/ctime stability,
complete UTF-8/JSONL records, unique event IDs, strict receipt keys and
the controller's before/after state. It never writes, truncates, rotates or
repairs the journal. Read errors, missing or partial files, duplicated,
unknown or malformed entries, changed files and controller drift all
require manual intervention.

Each report exposes only non-secret fields: sanitized process state,
last terminal state/error code/UTC timestamp/event ID, journal entry count,
SHA256 of observed bytes, and manualInterventionRequired. A historical
FAILED receipt remains a manual-review HOLD even after a later STOPPED
receipt; a later apparently clean process cannot silently clear an old
fault. CLEAN_STOP is solely an observation of a stopped local controller
and a valid journal, not a release or reactivation approval.

guardian-local-operator-session.cjs composes existing Controller, receipt
Journal and read-only Diagnostics but returns **separate frozen owner and
operator capabilities**: owner can start/stop/status; operator can inspect
only. The Operator object has no start, stop, recovery, token, D1 write,
Check publishing or journal reset method. It is not an HTTP endpoint,
not a live service and not accessible outside the local owner boundary.

The new offline tests exercise real Protected Host child start/stop,
durable failure receipts across separate process instances, manually
persistent faults, repeated read-only inspections without changing file
bytes/mtime, symlinks, partial JSON, ownership or quota failures, and
untrusted status or input. It is not hosted Cloudflare D1 E2E, real
GitHub App Check issuance, native non-author GitHub Approval or production
readiness. The active Founder launch HOLD remains binding.


## G18 — Read-only Operator event window and incident evidence (source-only)

The local diagnostic reader now exposes recentEvents({ limit, cursor }) through
the isolated Operator capability. The owner-only start/stop/status capability
is unchanged. Default limit is 10, maximum is 50, and queries always validate
the entire bounded JSONL journal (including duplicate JSON keys, event IDs,
record schema, file owner/permissions, symlinks, file changes and controller
state). They never create a file, clear errors, spawn a child or write to D1.

Pages return the newest events first and only the four allowlisted fields
eventId, timestamp, state and errorCode. An opaque-in-purpose, explicitly
nonsecret cursor contains the observed journal SHA-256 and preceding row
offset. Any changed journal invalidates the cursor and returns no events;
there is no cached page, hidden pagination state or implicit restart. Cursor
hashes identify the local observed bytes only and are NOT authentication,
integrity attestation, authorization, liveness proof or release tokens.

Each validated page includes an immutable incident summary containing
failureCount, firstFailure, latestFailure and manualInterventionRequired.
Any historical FAILED receipt continues to require manual intervention even
after a later successful STOPPED receipt. There is no fault acknowledgment,
reset, erase, override, approval or release endpoint; source remains HOLD.

Both inspect() and recentEvents() use the same journal/controller validation
snapshot. On corrupt, missing, truncated, swapped or unauthorized files, or
an unverified controller, the event page carries zero rows and fail-closed
SOURCE_ONLY_HOLD. Query input failures produce fixed nonsecret error codes.

This is a local observer for an already owned child lifecycle only. It does
not provide operator authentication, a daemon interface, a durable custody
ledger, a trust anchor or production acceptance.


## G19 — Immutable local fault evidence packet (source-only)

A local Operator can now call incidentEvidence({ eventId, journalSha256 })
on its read-only capability. Both fields are optional: an omitted event ID
selects the latest FAILED receipt in the currently validated journal. An
explicit event ID selects only that exact FAILED event, never silently
substituting a newer one. The optional journalSha256 is an optimistic
snapshot binding: if the bytes changed since the caller last observed them,
the query returns UNAVAILABLE with zero selected receipt details. Invalid
inputs (including object accessors, unexpected keys, symbols and unsafe
Proxy traps) reject before touching the journal.

One protected journal/controller read supplies the packet. It checks the
same owner-only storage permissions, complete bounded JSONL, unique receipt
IDs, duplicate JSON keys, file metadata stability, and controller state
before/after as the prior inspect/recentEvents APIs. No second,
potentially divergent file read is used to assemble the packet.

The bounded fault packet contains only allowlisted terminal-receipt metadata:
the selected failure's 1-based sequence, adjacent preceding/following
receipts, first and last failure, failure count, total event count, current
controller observation reason, SHA-256 of journal bytes and SHA-256 of the
canonical returned packet fields (excluding its own evidenceSha256 field).
The packet digest is deterministic for equivalent observations. No raw JSON,
PID, App private key, bearer token, process env, error message, D1 payload,
webhook content, arbitrary file path, credential or personal identifier is
returned. The packet is frozen, read-only and bounded to five selected event
metadata objects regardless of the journal length.

If there is no FAILED event, an unrecognized event ID, a STOPPED event ID,
a stale snapshot, a missing/corrupt/untrusted journal, or controller drift,
the packet is UNAVAILABLE; it contains no selected event, digest or
fault-context metadata and maintains manualInterventionRequired=true.
A historical FAILED remains recorded and requires manual review even when
subsequent process lifetimes append clean STOPPED receipts.

authority=LOCAL_UNAUTHENTICATED_OBSERVATION is deliberate: SHA-256 is a
comparison digest, NOT a signature, independent attestation, append-only
storage proof, permission to restart, evidence of process liveness or Check
release authority. A write-capable local adversary can replace the file and
recompute the digest. No export/upload endpoint, automatic approval,
acknowledge, reset, Check publication or hosted mapping is introduced.


G19 hardening additionally rechecks the pinned evidence directory's inode,
ownership and restricted mode on EACH observation, before and after reading
its journal. A directory replaced or made writable by other users after
the diagnostics constructor ran cannot silently result in a clean report.
Controller status fields are taken once from ordinary own data properties,
not accessors or unrecognized status fields; malformed/hostile status
objects are unverified, never a basis for a clean stop or fault packet.

## G20 — Independent read-only local incident packet comparison (source-only)

The separate `guardian-local-evidence-verifier.cjs` module accepts an
existing G19 `incidentEvidence()` packet and compares it with the exact
owner-owned local journal bytes read from a private owner-configured file.
It NEVER calls `incidentEvidence()` or relies on any of the packet's
reported fields as the source of truth. It independently validates the
whole bounded journal: duplicate JSON fields and event IDs, schema,
timestamps, state, owner-only file permissions, pinned directory identity,
file inode/size/metadata stability and SHA-256 over actual observed bytes.

Only packets with an exact field allowlist, data properties, fixed
non-authorizing values and a reconstructed canonical packet SHA-256
are considered for comparison. MATCH requires the same journal bytes,
event count, selected failure position, preceding/following receipts,
first/latest failures and failure count. A forged or stale context fails
closed, even if a caller recomputes the packet digest. Responses are
fixed-size, frozen and sanitized: no raw journal, arbitrary error, key,
token, PID, Check payload or path is returned.

The Operator-only facade exposes `verifyIncidentEvidence(packet)`.
Its positive result is deliberately `MATCH_LOCAL_SNAPSHOT_ONLY`, NOT
proof of trusted source custody or process-controller identity. Both
positive and negative outcomes preserve SOURCE_ONLY_HOLD,
manualInterventionRequired=true, activationAllowed=false,
automaticRestartAllowed=false and releaseAuthority=NOT_ISSUED.

Scope limit: this proves internal consistency with local readable bytes
at one observation, NOT process liveness, independent custody, evidence
signatures, restart approval, audit-grade provenance, hosted D1 integrity
or authorization to publish any GitHub Check. A local write-capable
adversary can replace the journal AND reconstruct both digests. No
signing keys, credentials, writable operator APIs, Merge, Deploy or
activation transitions are added.

## G21 — Read-only local append-continuity witness (memory-only, source-only)

The G20 verifier now also exposes `observeContinuity()` using the SAME
protected journal reader; the separated Operator facade exposes
`observeLocalContinuity()`. This is not an exporter, release gate, new
process manager or hosted activation path. Construction/import do no I/O;
the first explicit observation reads only the pinned, owner-only journal.

The first complete and valid journal read establishes a local untrusted
baseline. Later observations validate the entire bounded JSONL again and
require the same device/inode, nondecreasing length and event count, and an
exact SHA-256 match of the prior known bytes as the prefix of the new file.
A byte-identical repeat preserves the same step; new validated receipts
advance the local chain once, with an explicit count of new entries.
The local chain hash deterministically links prior chain hash, journal
SHA-256, record count and byte length. It is NOT signed, a durable ledger
or an external trust anchor. The observer accepts no caller-supplied path,
baseline digest, restart approval or override.

Once a baseline exists, a valid file with changed historical bytes,
truncated history, replaced inode, malformed/duplicate receipts or
owner-permission drift permanently latches the observer into NOT_VERIFIED
for its lifetime. Before the first baseline, a missing journal returns
NOT_VERIFIED/HOLD without latching (allowing the first child to create it).
No Operator method
can reset or clear it. A new instance yields only a NEW untrusted baseline:
it cannot claim the old instance's observations or cross-process continuity.

The result is bounded and frozen: local step count, prior/current digest,
added entry count, internal chain digest and fixed non-authorizing safety
flags; no PID, raw journal, credentials, file paths or keys.
`status=SOURCE_ONLY_HOLD`, `manualInterventionRequired=true`,
`custodyVerified=false`, `externalAnchorVerified=false`,
`activationAllowed=false`, `automaticRestartAllowed=false`, and
`releaseAuthority=NOT_ISSUED` are invariant, even on a positive append
comparison. Relative detection is against the immediately preceding
in-process observation. It does not establish independent custody, protect
against a hostile writer before first read or persist an anchor on restart.
No D1, GitHub App, Check publication or deployment actions are introduced.


## G22 — Operator-only bounded fault triage and manual action cues (source-only)

guardian-local-diagnostics.cjs now exposes faultTriage() from exactly
one protected, owner-owned journal read and one validated Controller status
observation. The separated guardian-local-operator-session.cjs facade
exposes the same read-only method to Operators without modifying the Owner
start/stop surface. Import and construction remain inert.

A frozen allowlisted summary provides a four-level local investigation
priority (P0 through P3), static classification/next-action codes, state,
journal count/hash and first/latest recorded failure IDs/timestamps/error
codes. It does NOT return a PID, file path, raw JSONL, credentials, arbitrary
exception messages, GitHub Check payload, restart controls or raw D1 data.

- **P0 EVIDENCE_UNVERIFIED:** Controller identity/state or journal evidence
  is inaccessible, malformed, replaced, insecure or changed during read;
  Owner must investigate protected local evidence. This is not a confirmed
  tampering claim. A RUNNING Controller without a terminal journal is also
  P0, because it cannot be verified from persisted receipts alone.
- **P1 RECORDED_FAILURE / CONTROLLER_FAILED:** any previously validated FAILED
  receipt, *even after later STOPPED receipts*, or a currently failed
  Controller. Owner must review history or investigate controller failure.
- **P2 NO_LOCAL_BASELINE / PROCESS_STATE_UNPROVEN:** an inert CREATED
  Controller before its first journal exists, or a non-terminal lifecycle
  state with a valid prior journal; Owner must verify prerequisites or
  reconcile process lifecycle, not infer liveness from local receipts.
- **P3 LOCAL_STOP_OBSERVED:** valid owner-only journal contains no historical
  failure and Controller says STOPPED, representing only one local clean-stop
  observation; no runtime/production trust can be inferred.

status=SOURCE_ONLY_HOLD, liveness=NOT_PROVEN, activationAllowed=false,
automaticRestartAllowed=false, releaseAuthority=NOT_ISSUED remain
invariant in ALL branches. Even P3 is NOT authorization for automatic
restart, GitHub Check release, D1 mutation, or launching production services.

P0–P3 are deterministic manual investigation ordering hints, not a
verified operational incident severity or authority decision. An attacker
with filesystem write rights can still replace the journal and recompute
digests before a fresh observation. The new tests cover the actual isolated
Protected Host child process, historical failure persistence, malformed
journal, symlink/permission violations, Controller state drift/getters,
pure-read behavior and strict output boundaries. No live environment
actions, keys, Merge, Deploy or permission mutation were added.


## G23 — Bounded on-demand active child health probe (source-only)

Previously the Operator's RUNNING status was only an IPC READY receipt
captured when the child started; it did not establish whether the child or
the protected loopback listener continued responding. This batch adds an
explicit, read-only health challenge, NOT a restart/watchdog/activation path.

The owner-pinned parent Controller now exposes probeRuntime(), and the
separated Operator facade exposes only the same asynchronous read. The
parent generates a 128-bit random challenge, sends a fixed-shape
HEALTH_PROBE to its own ChildProcess IPC channel, and accepts a fixed-shape
HEALTH_RESULT only with that exact outstanding challenge. The real child
re-checks its current Protected Host Runner status and the loopback
/healthz endpoint before returning a boolean. Neither side sends a raw
Host status, D1 access, PID, credentials, network address, token, exception
text or Check publication capability through IPC. A verified local probe
means a recent *local child IPC + loopback roundtrip only*, not OS identity,
outside-origin reachability, auditable custody or release authorization.

Simultaneous callers coalesce into one request, and Owner config bounds
the deadline to 50–5000ms (default 3000ms). Unresponsive/malformed/false
responses cannot be used to claim liveness; a timeout or negative health
latches further probes into NOT_PROVEN for that controller lifetime. One
late, valid response to the expired challenge is ignored rather than
resurrecting trust. Unknown or mismatched protocol frames remain the
existing fail-closed Controller protocol violations. A stop during an
in-flight probe resolves the read as NOT_PROVEN; it never delays shutdown.
Import and construction remain inert; probeRuntime() never calls start(),
stop(), signal(), reset(), D1 or GitHub. The Owner is still the only side
allowed to start/stop the child, and probes do not mutate the journal.

A frozen, sanitized result always includes SOURCE_ONLY_HOLD,
manualInterventionRequired=true, activationAllowed=false,
automaticRestartAllowed=false and releaseAuthority=NOT_ISSUED. Even the
positive observation is NOT a launch approval.

Source-only tests use the actual Protected Host child and loopback socket,
as well as disposable synthetic children for stale, false, forged,
unsolicited, extra-field, timeout, coalescence, stop-race and configuration
boundary cases. No production listener, hosted D1, real GitHub App Check
issuer, credential changes, Merge or Deploy are part of this feature.

## G24 — Ephemeral local probe freshness & state drift (source-only)

The existing Operator probeRuntime() remains an explicit, bounded IPC +
loopback probe. Its result is now recorded by an inert, in-memory observation
facade. Operator may additionally call observeRuntimeHealth() to inspect
whether its own last successful probe is within a pinned, bounded monotonic
age window (50–30000ms, default 1000ms). Passive observation does not send
IPC, touch the journal, issue Check, start/stop or auto-retry the child.

Freshness is not ongoing liveness. Even a recent snapshot reports
liveness=NOT_PROVEN, SOURCE_ONLY_HOLD, manual intervention required,
no restart, no activation and no release authority. It exposes only a
timestamp, elapsed milliseconds and bounded reason, never PID, challenge,
secret or raw payload. The snapshot expires monotonically and is invalidated
on unexpected controller state, PID/error changes, rejected active probe or
Owner stop. All sample state is volatile and cannot survive process restart
as a bogus durable attestation. Invalid/proxy-like status or forged payload
are rejected or sanitized fail-closed.

Tests cover both a real isolated Protected Host child and deterministic
negative scenarios for stale probe, state/PID drift, malformed response,
probe failure, concurrent requests, read-only passive inspection and invalid
configuration. No reviewer, production D1, GitHub App, Check issue, Merge,
Deploy, permission change or credentials are part of this batch.


## G25 — Operator passive runtime assessment and fault priority (source-only)

The isolated Operator facade now exposes assessRuntime(), a **synchronous,
read-only** fusion of existing faultTriage() and observeRuntimeHealth().
It is not a health probe, daemon monitor, liveness certification, Check
publisher, recovery action or permission to clear HOLD. It creates no new
credentials and does not alter the owner-controlled start/stop methods.

The assessment brackets those two readings with sanitized Controller status
snapshots. A changed state/PID/error, malformed or inconsistent evidence,
exception or unexpected authority field forces P0
LOCAL_OBSERVATION_UNVERIFIED with an owner-only investigation recommendation.
Only whitelist primitives from either underlying source reach the result;
raw receipts, child PID, filesystem paths, tokens, exceptions and secrets are
not included. The facade performs no IPC or probeRuntime() call.

P0 invalid/uncertain evidence and P1 recorded historic faults retain their
existing priority regardless of a recent local probe. P2 RUNNING observations
are distinguished as RECENT_LOCAL_PROBE_ONLY, LOCAL_PROBE_EXPIRED or
NO_VERIFIED_HEALTH_SAMPLE to guide which local read the owner should request;
all remain manual-intervention and SOURCE_ONLY_HOLD. Clean stopped P3 remains
only a local observation; no restart/activation/Check authority is granted.
Health samples are bounded by their original volatile monotonic freshness
window. There is no assurance the process stayed healthy between or after
the two reads, nor protection against an already compromised local process or
an attacker who can rewrite both local files and baselines.

Tests cover a real protected child lifecycle with an isolated temporary
journal plus deterministic P0/P1/P2/P3, freshness, malformed fields, controller
drift, no-side-effects and exception/non-leakage scenarios. Hosted D1,
production process identity, GitHub App Check signer, independent QA and
deployment acceptance remain outside this source-only development batch.


## G26 — bracketed runtime/journal race consistency (source-only)

G25's passive assessRuntime() now uses a bounded double-journal/triage
read around a single health-observation read, plus three sanitized
Controller snapshots (before, between and after). Both independently
observed journal histories must agree on protected SHA-256, event count,
fault count, classification, source reason, process state and owner action.
Each Controller snapshot must agree on state, PID and error code. Any
mismatch, mid-read journal append/replacement, missing baseline transition,
hostile getter or thrown reader causes P0 LOCAL_OBSERVATION_UNVERIFIED,
manual owner investigation and SOURCE_ONLY_HOLD. G26 never retries or
corrects evidence, never probes/starts/stops a child and never clears HOLD.

A RECENT health sample is also checked against elapsed monotonic time spent
across both journal reads: if it has aged beyond its own pinned max-age by
the end of the bracket, the result becomes P0 instead of retaining RECENT.
There is no new Check authority, no raw journal payload or PID in results.

These checks detect observable races, not a linearizable multi-source OS
transaction: extremely brief process/journal changes that return to
byte-identical values between observation points (ABA), or compromise of
all local evidence, remain outside their proof. The status always returns
liveness=NOT_PROVEN, activationAllowed=false,
releaseAuthority=NOT_ISSUED and automaticRestartAllowed=false.
Negative tests deliberately mutate journal metadata during the health
read, append a real protected receipt, vary the mid-snapshot PID, poison
the second read with exceptions/getters, and expire a RECENT observation
while the second read is delayed. No reviewer or production activation
is performed mid-batch.

## G31A — read-only terminal callback / receipt persistence diagnosis

The separated Operator facade exposes diagnoseTerminalPersistence(), a
source-only, read-only P0/P1/P2/P3 triage adapter. It brackets two existing
protected journal faultTriage() reads with three sanitized Controller status
snapshots; PID/generation/error changes or journal digest drift return P0
OBSERVATIONS_INCONSISTENT without exposing paths, PIDs or raw event data.

A Controller terminal callback failure (GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED)
is reported as P0 TERMINAL_CALLBACK_FAILURE_OBSERVED, even if the journal
contains older successful stops. It directs the Owner to investigate the
terminal receipt path. It does NOT assert that storage specifically failed:
an unexpected synchronous terminal callback exception can produce the same
Controller error. All results preserve SOURCE_ONLY_HOLD, no automated recovery,
no evidence certification and no new release/Check authority. The feature
never probes, starts/stops children, opens files directly or writes evidence.

The diagnosis accepts both the original v1 Controller/triage fields and the
optional generation ID, unterminated and concurrent counters staged in the
separate G27–G30 branches. Their transitions also invalidate a stale read;
the PR remains independently based on PR #15 and does not modify those Writers.


## G33A — Operator local filesystem pressure triage (source only)

The read-only assessJournalStorage() Operator method composes the existing
protected assessJournalBudget() journal-file identity/limit checks with two
bounded statfs observations of the owner-scoped local directory. Three
Controller snapshots bracket the reads; generation/state/PID drift, journal
identity/size changes, malformed or missing filesystem statistics, unsafe
permissions, symlinked directory, or changing filesystem type fail P0.

The smaller available-block sample determines local pressure: below 1 MiB is
P1, below 8 MiB is P2, otherwise P3 only if the journal-file limit also has
P3 headroom. A journal-file P1/P2 risk retains its priority even on a filesystem
with ample free blocks. Returned free-capacity telemetry is saturated at 64 MiB
for privacy; it is not an exact disk-space quantity, guaranteed reservation,
permission to append, successful fsync, liveness proof or evidence attestation.
The read never probes or starts/stops children, writes files, touches production
D1, releases HOLD or emits a Check. An attacker with control of the local
filesystem or a mount change/ABA between sampling instants can defeat this
best-effort observation; all results retain SOURCE_ONLY_HOLD and human review.

## G34A — Operator terminal callback / storage risk correlation (source only)

The read-only `assessTerminalStorage()` Operator method correlates existing
`diagnoseTerminalPersistence()` and `assessJournalStorage()` without a
new journal reader, Check issuer, process probe or writer. Three sanitized
Controller snapshots bracket two independently obtained samples from EACH
source. A PID, generation, state, error-code or receipt-field change is P0
`CORRELATION_EVIDENCE_UNVERIFIED`, with no partial evidence disclosed.

P0 terminal callback failures always remain P0 even when sampled filesystem
space is ample. A coincident low-storage observation is reported separately,
but **causalLinkVerified=false**: a throwing terminal callback is not proof
of an ENOSPC error. P1 historic faults or critical journal/storage pressure
cannot be downgraded by a P2/P3 source. Any malformed evidence, unknown
authority field, non-data descriptor or inconsistent process state is P0.
Valid clean STOPPED / spacious snapshots are at most P3 *local observations*.

The fixed, frozen receipt carries only allowlisted priorities and states; no
PID, path, raw journal bytes, exception, tokens or keys. It always reports
`SOURCE_ONLY_HOLD`, `liveness=NOT_PROVEN`,
`automaticRestartAllowed=false`, `activationAllowed=false`,
`releaseAuthority=NOT_ISSUED`; it cannot start/stop/restart children,
erase evidence, write D1, manage credentials or issue a real GitHub Check.

These samples are not an atomic filesystem transaction. A change-and-restore
(ABA) between reads, a compromised Controller, a malicious writer controlling
both journals, or a subsequent ENOSPC can escape detection. P3 never releases
HOLD. Independent non-author QA and production acceptance remain separate.

## G35A — PR #18 journal-identity integration and in-place continuity (OFF)

On the isolated PR #24 terminal/storage candidate, import PR #18's protected
receipt writer/tests without modifying PR #18. Add an in-memory SHA-256 and
exact byte-size continuity high-watermark to reject complete-line truncation,
same-inode same-size modification, or unexpected external append after a
successful write. The pre-append prefix is rechecked after fsync. Detected
drift fails closed without repair, rotation, deletion or release authority.
New writer instances cannot attest preexisting history; cross-process TOCTOU
races remain. No signed witness, cross-process lock or Check authority added.
