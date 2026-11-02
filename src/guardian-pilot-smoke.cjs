"use strict";

// PREPARATION ONLY.
// Future target path: src/guardian-pilot-smoke.cjs
//
// This fixture deliberately has no network, secret, merge, deployment or repository mutation.
// It gives the first-pilot evidence workflows a small deterministic program whose behavior can
// fail when source or tests drift.

function classifyPath(path) {
  if (typeof path !== "string" || path.length === 0) throw new Error("PATH_REQUIRED");
  if (path.startsWith("secrets/") || path === ".env") return "PRIVATE";
  if (path.startsWith("infra/production/") || path === ".github/workflows/deploy.yml") return "PROHIBITED";
  if (path.startsWith("src/") || path.startsWith("test/") || path.startsWith("docs/")) return "AUTHORIZED";
  return "OUTSIDE_ALLOWLIST";
}

module.exports = { classifyPath };
