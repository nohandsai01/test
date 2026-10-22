# Merge Gate CI Candidate — source-only delivery contract

Status: **SOURCE_ONLY / FEATURE_OFF / LAUNCH_HOLD**  
Repository: `nohandsai01/test`  
Authorized branch: `feat/merge-gate-ci-candidate-20261022`  
No hosted CI check, workflow issuer, reviewer identity, production, merge, or deployment proof is asserted.

## Delivered components

| File | Responsibility |
| --- | --- |
| `trusted-evidence.yml.example` | Non-executable workflow candidate stored outside `.github/workflows/`; both proposed jobs remain fail closed |
| `source-contract.json` / `source-contract.cjs` | Strict proposed check names, repository, branch and activation-OFF structural schema |
| `policy-source-binding.cjs` | Compare static `nohands.yml` required evidence (`tests`, `ci`) and reject any early trusted workflow mapping |
| `verify-source-lock.cjs` / `source-lock.json` | Compare the exact Git blob SHA-1 of the pinned candidate source files |
| `error-codes.json` | Machine-readable allowlist of source-only error codes and their issuing stages |
| `candidate-preflight.cjs` | One entry point: combines contract, policy, locked bytes and catalog validation |

The source lock explicitly excludes `source-lock.json` itself to avoid a recursive hash. It is a **change detector for the pinned source set**, not a signed integrity attestation. A malicious party with write permission could modify both source and lock; authoritative controls must independently establish GitHub run identity and workflow provenance.

## Proposed offline invocation (NOT executed in this delivery)

From the repository root:

```sh
node merge-gate-install/candidate/candidate-preflight.cjs .
```

Never configure this command as a successful hosted CI check. The program deliberately never returns exit code `0`.

| Exit code | Meaning | Permits activation? |
| --- | --- | --- |
| `1` | Source input, policy, catalog or version validation failed | No |
| `2` | Invalid command-line invocation | No |
| `3` | Source structure matches the inert candidate; **not a CI success** | No |

## Output contract

```json
{
  "errorCodeSchemaVersion": 1,
  "status": "CANDIDATE_SOURCE_PREPARED_ONLY",
  "mode": "SOURCE_ONLY",
  "trusted": false,
  "activationAllowed": false,
  "hostedCheckEvidence": "NOT_VERIFIED",
  "checks": {
    "contract": "CANDIDATE_SOURCE_ONLY",
    "policy": "POLICY_BOUND_SOURCE_ONLY",
    "sourceLock": "SOURCE_BYTES_MATCH_CANDIDATE_LOCK"
  },
  "findings": []
}
```

The object above documents the **target structure**, not an observed execution result. If any finding occurs, `status` becomes `CANDIDATE_SOURCE_REJECTED`, and it includes entries shaped as `{ "stage": "...", "code": "...", "detail": "..." }`. In either state the trust and activation flags always remain false.

## Error categories

| Stage | Example codes | Operator meaning |
| --- | --- | --- |
| `contract` | `WRONG_REPOSITORY_OR_BRANCH`, `ACTIVATION_GATE_NOT_OFF`, `UNAPPROVED_CHECK_NAME` | Candidate metadata or names were altered |
| `policy` | `REQUIRED_EVIDENCE_DRIFT`, `TRUSTED_MAPPING_PREMATURE` | Repository policy differs from the authorized source-only baseline |
| `source_lock` | `SOURCE_LOCK_BLOB_DRIFT`, `SOURCE_LOCK_UNEXPECTED_SOURCE` | Candidate file bytes or pinned scope differ |
| `input` | `CANDIDATE_PREFLIGHT_INPUT_UNREADABLE` | A required local input could not be parsed or read |
| `catalog` | `ERROR_CATALOG_INVALID`, `ERROR_CATALOG_UNMAPPED_CODE` | Error schema malformed or code missing from allowlist |

Complete allowed code inventory is in `error-codes.json`; it includes standalone inspectors' read-error codes. The `catalog` error codes are internal fail-closed guards against the catalog itself.

## Out of scope and release boundary

- No live workflow under `.github/workflows/`, and no alteration to GitHub Actions settings.
- No new required status checks on `main` and no branch protection change.
- No live GitHub run fetch, trusted issuer mapping, signing or reviewer attestation.
- No test execution, QA, deployment, merge, production payment or secret handling.
- `tests` and `ci` are **proposed labels only** until separately provisioned and verified as genuine hosted check contexts.

Future activation requires a separate authorization and a new, independently reviewed branch/PR after the actual workflow source, trusted writer identity, exact GitHub run association and branch protection status checks are proven. No artifact in this candidate grants that authority.
