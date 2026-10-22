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

Source-only integration still needs the independently operated service host,
registered GitHub App identity, verified installer account binding, durable
data store, rate limits, observability, approved keys, active branch ruleset,
and a separate final acceptance gate. There is no attempt to provision any of
those resources in this batch.

Additional official references:

- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
- https://docs.github.com/en/rest/apps/apps
- https://docs.github.com/en/apps/sharing-github-apps/sharing-your-github-app
- https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url

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
- https://docs.github.com/en/rest/checks/suites
- https://docs.github.com/en/rest/apps/installations
- https://docs.github.com/en/rest/pulls/pulls
- https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
- https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

No tests, QA, demo, hosted CI, deployment, or real payment is performed in
this delivery batch.
