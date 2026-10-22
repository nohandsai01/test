/**
 * Immutable-shape guard for the inert hosted-CI workflow example.
 *
 * This is an exact allowlist of the approved NON-EXECUTABLE source bytes,
 * not a YAML parser and not a GitHub check, issuer, or workflow attestation.
 * The separate source lock also binds this file by Git blob hash.
 */
'use strict';

const fs = require('node:fs');

const APPROVED_LINES = Object.freeze([
  "# PREPARATION ONLY: non-executable .example outside .github/workflows.",
  "# No hosted check or CI evidence is created by committing this file.",
  "# Do not copy into .github/workflows without a separate Founder activation approval.",
  "name: NO HANDS Merge Gate Evidence Candidate",
  "",
  "on:",
  "  push:",
  "    branches: [main]",
  "  pull_request:",
  "    types: [opened, synchronize, reopened]",
  "",
  "permissions:",
  "  contents: read",
  "",
  "jobs:",
  "  tests:",
  "    name: NO HANDS Merge Gate / tests",
  "    runs-on: ubuntu-latest",
  "    timeout-minutes: 5",
  "    steps:",
  "      - name: Reject unapproved test evidence issuer",
  "        shell: bash",
  "        run: |",
  "          echo '::error title=TESTS_EVIDENCE_NOT_APPROVED::No source-bound hosted test runner or trustworthy test command has been approved.'",
  "          exit 1",
  "",
  "  ci:",
  "    name: NO HANDS Merge Gate / ci",
  "    runs-on: ubuntu-latest",
  "    timeout-minutes: 5",
  "    steps:",
  "      - name: Reject unapproved CI evidence issuer",
  "        shell: bash",
  "        run: |",
  "          echo '::error title=CI_EVIDENCE_NOT_APPROVED::No source-bound hosted CI runner or authoritative last-push evidence has been approved.'",
  "          exit 1"
]);
const APPROVED_TEMPLATE = APPROVED_LINES.join('\n') + '\n';

function inspectWorkflowTemplate(sourceText) {
  const findings = [];
  if (typeof sourceText !== 'string') {
    findings.push({
      code: 'WORKFLOW_TEMPLATE_INPUT_INVALID',
      detail: 'Expected exact UTF-8 workflow example source text.',
    });
  } else if (sourceText !== APPROVED_TEMPLATE) {
    findings.push({
      code: 'WORKFLOW_TEMPLATE_DRIFT',
      detail: 'The non-executable example changed from the approved fail-closed template.',
    });
  }
  return {
    status: findings.length ? 'WORKFLOW_TEMPLATE_REJECTED' : 'WORKFLOW_TEMPLATE_SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    findings,
  };
}

function main(args) {
  if (args.length !== 1) {
    process.stderr.write('Usage: node workflow-source-binding.cjs <trusted-evidence.yml.example>\n');
    return 2;
  }
  let sourceText;
  try {
    sourceText = fs.readFileSync(args[0], 'utf8');
  } catch (_) {
    process.stdout.write(JSON.stringify({
      status: 'WORKFLOW_TEMPLATE_REJECTED',
      trusted: false,
      activationAllowed: false,
      hostedCheckEvidence: 'NOT_VERIFIED',
      findings: [{
        code: 'WORKFLOW_TEMPLATE_UNREADABLE',
        detail: 'Cannot read the supplied workflow example.',
      }],
    }) + '\n');
    return 2;
  }
  const result = inspectWorkflowTemplate(sourceText);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  // Source-only inspection cannot be a green hosted CI check.
  return result.findings.length ? 1 : 3;
}

module.exports = { inspectWorkflowTemplate };
if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
