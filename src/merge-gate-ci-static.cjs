'use strict';

// Independent static CI only. This is not a Guardian decision or a substitute
// for the separately run Tests workflow, signed push evidence, or human review.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createRequire, builtinModules } = require('node:module');

const root = path.resolve(__dirname, '..');
const roots = ['src', 'test', 'merge-gate-install/candidate',
  'merge-gate-install/guardian-candidate'];
const required = [
  'test/merge-gate-candidate.test.cjs',
  'test/guardian-full-source.test.cjs',
  'merge-gate-install/candidate/source-contract.cjs',
  'merge-gate-install/candidate/verify-source-lock.cjs',
  'merge-gate-install/guardian-candidate/signed-policy.cjs',
  'merge-gate-install/guardian-candidate/guardian-webhook-runtime.cjs',
];
const jsonFiles = [
  'package.json',
  'package-lock.json',
  'merge-gate-install/candidate/source-contract.json',
  'merge-gate-install/candidate/source-lock.json',
  'merge-gate-install/candidate/error-codes.json',
];
// Node 24 contains node:-only built-ins. Never manufacture bare-name aliases
// for them; the internal module prefix is part of their valid specifier.
const builtins = new Set(builtinModules.flatMap((id) =>
  id.startsWith('node:') ? [id] : [id, `node:${id}`]));
const jsFile = /\.(?:cjs|mjs|js)$/;
const testFile = /\.test\.(?:cjs|mjs|js)$/;

function fail(message) {
  throw new Error(`SOURCE_CI_HOLD: ${message}`);
}

function trackedFiles() {
  const result = spawnSync('git', ['ls-files', '-z', '--', ...roots], {
    cwd: root, encoding: 'buffer', maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    fail('unable to enumerate tracked source with git');
  }
  const entries = result.stdout.toString('utf8').split('\0').filter(Boolean);
  if (!entries.length || entries.length > 1000 || new Set(entries).size !== entries.length) {
    fail('empty, excessive, or duplicate tracked source inventory');
  }
  return entries;
}

function regularTrackedFile(relativePath) {
  const absolute = path.resolve(root, relativePath);
  if (!absolute.startsWith(`${root}${path.sep}`)) fail(`path escaped repository: ${relativePath}`);
  const status = fs.lstatSync(absolute);
  if (!status.isFile() || status.isSymbolicLink()) fail(`not a regular file: ${relativePath}`);
  const real = fs.realpathSync(absolute);
  if (real !== absolute) fail(`file resolves through a link: ${relativePath}`);
  return absolute;
}

function checkSyntax(file) {
  const result = spawnSync(process.execPath, ['--check', file], {
    cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0) fail(`JavaScript syntax invalid: ${path.relative(root, file)}`);
}

function checkLiteralRequires(file, tracked) {
  const code = fs.readFileSync(file, 'utf8');
  const localRequire = createRequire(file);
  const pattern = /\brequire\s*\(\s*(['"])([^'"\\\r\n]+)\1\s*\)/g;
  for (const match of code.matchAll(pattern)) {
    const specifier = match[2];
    if (builtins.has(specifier)) continue;
    if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
      fail(`undeclared package import in ${path.relative(root, file)}: ${specifier}`);
    }
    let resolved;
    try {
      resolved = localRequire.resolve(specifier);
    } catch (_) {
      fail(`unresolved relative import in ${path.relative(root, file)}: ${specifier}`);
    }
    if (!resolved.startsWith(`${root}${path.sep}`)) {
      fail(`import escapes repository: ${path.relative(root, file)}`);
    }
    const relativeResolved = path.relative(root, resolved);
    if (!tracked.has(relativeResolved)) {
      fail(`untracked relative import in ${path.relative(root, file)}: ${specifier}`);
    }
    regularTrackedFile(relativeResolved);
  }
}

function main() {
  const files = trackedFiles();
  const tracked = new Set(files);
  for (const relative of required) {
    if (!tracked.has(relative)) fail(`required source missing from commit: ${relative}`);
  }
  const tests = files.filter((name) => name.startsWith('test/') && testFile.test(name));
  const guardian = files.filter((name) =>
    name.startsWith('merge-gate-install/guardian-candidate/') && jsFile.test(name));
  if (tests.length < 2 || guardian.length < 2) fail('meaningful test or Guardian source inventory missing');

  const scripts = files.filter((name) => jsFile.test(name));
  for (const relative of scripts) {
    const file = regularTrackedFile(relative);
    checkSyntax(file);
    checkLiteralRequires(file, tracked);
  }
  for (const relative of jsonFiles) {
    const file = regularTrackedFile(relative);
    try { JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (_) { fail(`invalid JSON: ${relative}`); }
  }
  console.log(`SOURCE_CI_STATIC_OK: ${scripts.length} source files, ${tests.length} test files; operational acceptance remains HOLD`);
}

try { main(); }
catch (error) {
  console.error(error instanceof Error ? error.message : 'SOURCE_CI_HOLD: unexpected error');
  process.exitCode = 1;
}
