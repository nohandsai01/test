"use strict";

// PREPARATION ONLY.
// Future target path: test/guardian-pilot-smoke.test.cjs

const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyPath } = require("../src/guardian-pilot-smoke.cjs");

test("authorized paths are recognized", () => {
  for (const path of ["src/index.js", "test/a.test.js", "docs/readme.md"]) {
    assert.equal(classifyPath(path), "AUTHORIZED");
  }
});

test("prohibited and private paths never collapse into authorized", () => {
  assert.equal(classifyPath("infra/production/deploy.sh"), "PROHIBITED");
  assert.equal(classifyPath(".github/workflows/deploy.yml"), "PROHIBITED");
  assert.equal(classifyPath("secrets/token.txt"), "PRIVATE");
  assert.equal(classifyPath(".env"), "PRIVATE");
});

test("outside-allowlist paths remain distinct", () => {
  assert.equal(classifyPath("package.json"), "OUTSIDE_ALLOWLIST");
});

test("invalid input fails closed", () => {
  assert.throws(() => classifyPath(""), /PATH_REQUIRED/);
});
