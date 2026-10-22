/**
 * Advisory CI diff-scope gate for the isolated Merge Gate candidate branch.
 * Not a trusted Check issuer: a branch author can change this code/workflow.
 */
'use strict';

const { execFileSync } = require('node:child_process');
const path = require('node:path');

const ALLOWED_FILES = new Set([
  'README.md',
  'nohands.yml',
  'test/merge-gate-candidate.test.cjs',
  '.github/workflows/merge-gate-candidate-qa.yml',
]);

function allowed(file) {
  return ALLOWED_FILES.has(file) ||
    /^merge-gate-install\/[A-Za-z0-9_.\/-]+$/.test(file);
}

function inspectChangedPaths(files) {
  if (!Array.isArray(files) || files.length === 0 ||
      files.some(file => typeof file !== 'string' || !file || file.startsWith('/') ||
        file.split('/').some(part => !part || part === '.' || part === '..'))) {
    return { status: 'CANDIDATE_CHANGE_SCOPE_REJECTED', findings: ['CHANGE_SCOPE_INPUT_INVALID'] };
  }
  const outOfScope = [...new Set(files.filter(file => !allowed(file)))].sort();
  return {
    status: outOfScope.length ? 'CANDIDATE_CHANGE_SCOPE_REJECTED' : 'CANDIDATE_CHANGE_SCOPE_ONLY',
    findings: outOfScope.map(file => 'OUT_OF_SCOPE:' + file),
    trusted: false,
    activationAllowed: false,
  };
}

function main(args) {
  if (args.length !== 1) {
    process.stderr.write('Usage: node check-change-scope.cjs <repository-root>\n');
    return 2;
  }
  let result;
  try {
    const cwd = path.resolve(args[0]);
    const diff = execFileSync('git',
      ['diff', '--name-only', '-z', '--diff-filter=ACDMRTUXB', 'origin/main...HEAD', '--'],
      { cwd, maxBuffer: 2_000_000, timeout: 10_000 });
    const raw = diff.toString('utf8');
    if (Buffer.from(raw, 'utf8').compare(diff) !== 0 || !raw.endsWith('\0')) {
      throw new Error('Invalid Git diff filename encoding.');
    }
    result = inspectChangedPaths(raw.slice(0, -1).split('\0'));
  } catch (_) {
    result = { status: 'CANDIDATE_CHANGE_SCOPE_REJECTED',
      findings: ['CHANGE_SCOPE_READ_UNAVAILABLE'], trusted: false,
      activationAllowed: false };
  }
  process.stdout.write(JSON.stringify(result) + '\n');
  return result.findings.length ? 1 : 0;
}

module.exports = { inspectChangedPaths };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
