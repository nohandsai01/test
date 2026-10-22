# Merge Gate CI Candidate — source-only delivery contract

Status: **SOURCE_ONLY / FEATURE_OFF / LAUNCH_HOLD**  
Repository: `nohandsai01/test`  
Source-declared scope: `feat/merge-gate-postqa-20261022` (not authenticated branch provenance)
No hosted CI check, workflow issuer, reviewer identity, production, merge, or deployment proof is asserted.

## Delivered components

| File | Responsibility |
| --- | --- |
| `trusted-evidence.yml.example` | Non-executable workflow candidate stored outside `.github/workflows/`; both proposed jobs remain fail closed |
| `source-contract.json` / `source-contract.cjs` | Single future Guardian-App required-check name, repository, source-declared branch, and activation-OFF schema |
| `policy-source-binding.cjs` | Compare static `nohands.yml` required evidence (`tests`, `ci`) and reject any early trusted workflow mapping |
| `workflow-source-binding.cjs` | Enforce exact inert template bytes and reject changes to the fail-closed workflow example; not hosted evidence |
| `verify-source-lock.cjs` / `source-lock.json` | Compare the exact Git blob SHA-1 of the pinned candidate source files |
| `error-codes.json` | Machine-readable allowlist of source-only error codes and their issuing stages |
| `candidate-preflight.cjs` | One entry point: combines contract, policy, locked bytes and catalog validation |

The workflow template guard is an exact-source allowlist, not a general YAML parser; changing either example job or its fail-closed command must be treated as a rejected candidate until separately authorized. The source lock explicitly excludes `source-lock.json` itself to avoid a recursive hash. It is a **change detector for the pinned source set**, not a signed integrity attestation. A malicious party with write permission could modify both source and lock; authoritative controls must independently establish an externally governed anchor, GitHub run identity and workflow provenance.

## Offline source-only invocation (may be used for non-authoritative QA)

From the repository root:

```sh
node merge-gate-install/candidate/candidate-preflight.cjs .
```

Never configure this command **or any standalone evidence inspector** as a successful hosted CI check. The preflight and evidence inspectors deliberately avoid exit code `0`, even when local source bytes match. The separate advisory `check-change-scope.cjs` can exit `0` when a diff stays in scope; that is only a developer-CI scope result, never hosted trust evidence.

The same nonzero success-equivalent rule applies to:

```sh
node merge-gate-install/candidate/source-contract.cjs merge-gate-install/candidate/source-contract.json
node merge-gate-install/candidate/policy-source-binding.cjs merge-gate-install/candidate/source-contract.json nohands.yml
node merge-gate-install/candidate/verify-source-lock.cjs merge-gate-install/candidate/source-lock.json .
node merge-gate-install/candidate/workflow-source-binding.cjs merge-gate-install/candidate/trusted-evidence.yml.example
```

These are local source-inspection invocations, not hosted trust issuers. Developer QA has separately executed non-authoritative source tests. Use the consolidated preflight for source-only handoff; do not register the individual tools as hosted required status checks.

| Exit code | Meaning | Permits activation? |
| --- | --- | --- |
| `1` | Source input, policy, catalog or version validation failed | No |
| `2` | Invalid command-line invocation | No |
| `3` | Source structure matches the inert candidate; **not a CI success** (also applies to each standalone inspector) | No |

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
    "workflowTemplate": "WORKFLOW_TEMPLATE_SOURCE_ONLY",
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
| `workflow_template` | `WORKFLOW_TEMPLATE_DRIFT`, `WORKFLOW_TEMPLATE_INPUT_INVALID` | Non-executable CI example no longer matches the approved fail-closed source |
| `source_lock` | `SOURCE_LOCK_BLOB_DRIFT`, `SOURCE_LOCK_UNEXPECTED_SOURCE` | Candidate file bytes or pinned scope differ |
| `input` | `CANDIDATE_PREFLIGHT_INPUT_UNREADABLE` | A required local input could not be parsed or read |
| `catalog` | `ERROR_CATALOG_INVALID`, `ERROR_CATALOG_UNMAPPED_CODE` | Error schema malformed or code missing from allowlist |

Complete allowed code inventory is in `error-codes.json`; it includes standalone inspectors' read-error codes. The `catalog` error codes are internal fail-closed guards against the catalog itself.

## Out of scope and release boundary

- No live workflow under `.github/workflows/`, and no alteration to GitHub Actions settings.
- No new required status checks on `main` and no branch protection change.
- No live GitHub run fetch, trusted issuer mapping, signing or reviewer attestation.
- Bounded source-only developer QA is allowed; no hosted trusted-check acceptance, deployment, merge, production payment or secret handling is authorized.
- `tests` and `ci` are **internal evidence types**, not GitHub required contexts. The sole eventual required context `NO HANDS Merge Gate Required Check` must be issued by the independently authenticated Guardian App, which this source-only candidate cannot impersonate.
- This candidate has no independently controlled lock anchor. The branch-local hash and its optional externally supplied digest primitive do **not** prove authoritative provenance; activation remains blocked.

Future activation requires a separate authorization and a new, independently reviewed branch/PR after the actual workflow source, trusted writer identity, exact GitHub run association and branch protection status checks are proven. No artifact in this candidate grants that authority.
