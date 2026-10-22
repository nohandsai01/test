/**
 * Structural binding of a SOURCE_ONLY CI candidate to nohands.yml.
 *
 * Deliberately rejects dynamic YAML features instead of interpreting them.
 * The authoritative Merge Gate parser and authenticated GitHub evidence loader
 * remain the only sources for runtime evidence and workflow provenance.
 * This module never authorizes activation or reports hosted CI PASS.
 */
'use strict';

const fs = require('node:fs');
const { validateCandidateContract } = require('./source-contract.cjs');

const EXPECTED = Object.freeze(['tests', 'ci']);

function add(findings, code, detail) {
  findings.push({ code, detail });
}

// Only a literal top-level YAML list is accepted here. This is an advisory
// source checker, not a general YAML parser or a substitute for Merge Gate.
function readLiteralTopLevelList(policyText, key, findings) {
  if (typeof policyText !== 'string') {
    add(findings, 'POLICY_TEXT_INVALID', 'Policy source must be UTF-8 text.');
    return null;
  }
  const lines = policyText.replace(/\r\n/g, '\n').split('\n');
  const headers = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^([A-Za-z_][A-Za-z_0-9]*):/.exec(lines[i]);
    if (match) headers.push({ index: i, key: match[1] });
  }
  const positions = headers.filter((item) => item.key === key);
  if (positions.length > 1) {
    add(findings, 'DUPLICATE_POLICY_SECTION', key);
    return null;
  }
  if (positions.length === 0) return undefined;

  const start = positions[0].index;
  if (!new RegExp('^' + key + ':[ \\t]*(?:#.*)?$').test(lines[start])) {
    add(findings, 'NON_LITERAL_POLICY_SECTION', key + ' must use a plain list.');
    return null;
  }
  const next = headers.find((item) => item.index > start);
  const end = next ? next.index : lines.length;
  const values = [];
  for (let i = start + 1; i < end; i += 1) {
    const line = lines[i];
    if (!line.trim() || /^[ ]*#/.test(line)) continue;
    const item = /^  - ([^\r\n]+)$/.exec(line);
    if (!item) {
      add(findings, 'POLICY_LIST_FORMAT_UNSUPPORTED', key + ' line ' + (i + 1));
      return null;
    }
    let value = item[1].trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      try { value = JSON.parse(value); }
      catch (_) {
        add(findings, 'POLICY_SCALAR_INVALID', key + ' line ' + (i + 1));
        return null;
      }
    } else if (value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1).replace(/''/g, "'");
    } else if (/[#\[\]{}&*!]/.test(value) || value.startsWith('- ')) {
      add(findings, 'POLICY_SCALAR_UNSUPPORTED', key + ' line ' + (i + 1));
      return null;
    }
    if (typeof value !== 'string' || !value.trim()) {
      add(findings, 'POLICY_SCALAR_EMPTY', key + ' line ' + (i + 1));
      return null;
    }
    values.push(value);
  }
  return values;
}

function inspectCandidatePolicy(manifest, policyText) {
  const contract = validateCandidateContract(manifest);
  const findings = [...contract.findings];
  const required = readLiteralTopLevelList(policyText, 'required_evidence', findings);
  const mappings = readLiteralTopLevelList(policyText, 'trusted_evidence_workflows', findings);

  if (required === undefined) {
    add(findings, 'REQUIRED_EVIDENCE_SECTION_MISSING', 'nohands.yml does not specify required_evidence.');
  } else if (Array.isArray(required)) {
    const unique = new Set(required);
    if (required.length !== EXPECTED.length || unique.size !== EXPECTED.length ||
        EXPECTED.some((key) => !unique.has(key))) {
      add(findings, 'REQUIRED_EVIDENCE_DRIFT', 'Expected exactly tests and ci.');
    }
  }

  // This development batch is intentionally not permitted to install mappings.
  // Any mapping entry, including one that looks valid, is activation drift.
  if (mappings !== undefined) {
    add(findings, 'TRUSTED_MAPPING_PREMATURE',
      'The source-only candidate must not configure trusted_evidence_workflows.');
  }

  return {
    status: findings.length ? 'POLICY_BINDING_REJECTED' : 'POLICY_BOUND_SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    findings,
  };
}

function main(args) {
  if (args.length !== 2) {
    process.stderr.write('Usage: node policy-source-binding.cjs <source-contract.json> <nohands.yml>\n');
    return 2;
  }
  let manifest;
  let policyText;
  try {
    manifest = JSON.parse(fs.readFileSync(args[0], 'utf8'));
    policyText = fs.readFileSync(args[1], 'utf8');
  } catch (_) {
    process.stdout.write(JSON.stringify({
      status: 'POLICY_BINDING_REJECTED',
      trusted: false,
      activationAllowed: false,
      hostedCheckEvidence: 'NOT_VERIFIED',
      findings: [{ code: 'INPUT_UNREADABLE', detail: 'Input files could not be parsed or read.' }],
    }) + '\n');
    return 2;
  }
  const result = inspectCandidatePolicy(manifest, policyText);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  return result.findings.length ? 1 : 0;
}

module.exports = { inspectCandidatePolicy, readLiteralTopLevelList };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
