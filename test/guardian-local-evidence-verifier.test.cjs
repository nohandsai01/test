'use strict';
// Independent G20 comparison of read-only G19 evidence against protected,
// owner-owned JSONL bytes. No live D1, GitHub App, Check, or network calls.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createGuardianLocalEvidenceVerifier } =
  require('../merge-gate-install/guardian-candidate/guardian-local-evidence-verifier.cjs');
const { createGuardianLocalDiagnostics } =
  require('../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const JOURNAL = 'guardian-g20-verification.jsonl';
const fixture = path.join(__dirname, 'guardian-protected-worker-child.cjs');
async function temporary(callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nh-g20-evidence-'));
  try { return await callback(dir); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
function pathTo(dir) { return path.join(dir, JOURNAL); }
function writer(dir) {
  return createGuardianLocalReceiptJournal({ directory: dir, fileName: JOURNAL });
}
function snapshotReader(dir) {
  return createGuardianLocalDiagnostics({
    directory: dir, fileName: JOURNAL,
    controller: { status: () => ({
      state: 'STOPPED', errorCode: null, pid: null,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    }) },
  });
}
function verifier(dir, opts = {}) {
  return createGuardianLocalEvidenceVerifier({
    directory: dir, fileName: JOURNAL, ...opts,
  });
}
function terminal(state = 'FAILED') {
  return {
    state,
    errorCode: state === 'FAILED' ? 'GUARDIAN_CHILD_EXIT_UNVERIFIED' : null,
    hostStopped: state === 'STOPPED',
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  };
}
function fill(dir, states) {
  const store = writer(dir);
  for (const state of states) store.append(terminal(state));
  return snapshotReader(dir).incidentEvidence();
}
function tamper(packet, change) {
  const obj = JSON.parse(JSON.stringify(packet));
  change(obj);
  const { evidenceSha256, ...fields } = obj;
  obj.evidenceSha256 = crypto.createHash('sha256')
    .update(JSON.stringify(fields)).digest('hex');
  return obj;
}
function safe(result) {
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.kind, 'GUARDIAN_LOCAL_EVIDENCE_COMPARISON_V1');
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.automaticRestartAllowed, false);
  assert.equal(result.manualInterventionRequired, true);
  assert.equal(result.controllerStateVerified, false);
  assert.equal(result.custodyVerified, false);
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.ok(Object.isFrozen(result));
  assert.equal(Object.hasOwn(result, 'pid'), false);
  assert.equal(Object.hasOwn(result, 'rawJournal'), false);
  assert.equal(Object.hasOwn(result, 'filePath'), false);
}
function reason(result, expected) {
  safe(result);
  assert.equal(result.reason, expected);
  assert.equal(result.comparison, expected ===
    'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH' ?
    'MATCH_LOCAL_SNAPSHOT_ONLY' : 'NOT_VERIFIED');
}

test('verifier is inert and absent local journal is never treated as evidence', async () => {
  await temporary(async (dir) => {
    const reader = verifier(dir);
    assert.deepEqual(Object.keys(reader).sort(), ['observeContinuity', 'verify']);
    assert.ok(Object.isFrozen(reader));
    assert.equal(fs.readdirSync(dir).length, 0);
    reason(reader.verify(null), 'GUARDIAN_EVIDENCE_PACKET_INVALID');
    assert.equal(fs.readdirSync(dir).length, 0);
  });
});

test('independent module matches a fully validated local fault packet without granting authority', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['STOPPED', 'FAILED', 'STOPPED', 'FAILED', 'STOPPED']);
    const before = fs.readFileSync(pathTo(dir));
    const info = fs.statSync(pathTo(dir));
    const result = verifier(dir).verify(packet);
    reason(result, 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
    assert.equal(result.inspectedEntries, 5);
    assert.equal(result.journalSha256, packet.journalSha256);
    assert.deepEqual(fs.readFileSync(pathTo(dir)), before);
    assert.equal(fs.statSync(pathTo(dir)).mtimeMs, info.mtimeMs);
    const again = verifier(dir).verify(packet);
    assert.deepEqual(again, result);
  });
});

test('selected historical fault, adjacent events, first/latest and exact order independently match', async () => {
  await temporary(async (dir) => {
    const last = fill(dir, ['FAILED', 'STOPPED', 'FAILED', 'STOPPED']);
    const firstId = last.firstFailure.eventId;
    const packet = snapshotReader(dir).incidentEvidence({
      eventId: firstId, journalSha256: last.journalSha256,
    });
    reason(verifier(dir).verify(packet), 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
    assert.equal(packet.eventSequence, 1);
    assert.equal(packet.previousReceipt, null);
    assert.equal(packet.nextReceipt.state, 'STOPPED');
    assert.notEqual(packet.selectedFailure.eventId, last.selectedFailure.eventId);
  });
});

test('valid standalone packet with recomputed hash but forged adjacent receipt is rejected', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['STOPPED','FAILED','STOPPED','FAILED']);
    const altered = tamper(packet, (p) => {
      p.previousReceipt = JSON.parse(JSON.stringify(p.firstFailure));
    });
    assert.equal(altered.journalSha256, packet.journalSha256);
    assert.notEqual(altered.evidenceSha256, packet.evidenceSha256);
    reason(verifier(dir).verify(altered),
      'GUARDIAN_EVIDENCE_PACKET_CONTENT_MISMATCH');
  });
});

test('valid re-hashed packet with forged count, position or first failure fails semantic comparison', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED','STOPPED','FAILED','STOPPED','FAILED']);
    const substitutions = [
      (p) => { p.failureCount = 2; },
      (p) => { p.eventSequence = 3; },
      (p) => { p.firstFailure = p.selectedFailure; },
      (p) => { p.latestFailure = p.firstFailure; },
      (p) => { p.journalEntries = 6; },
      (p) => { p.selectedFailure = p.firstFailure; },
      (p) => { p.nextReceipt = p.firstFailure; },
    ];
    const compare = verifier(dir);
    for (const mutation of substitutions) {
      const altered = tamper(packet, mutation);
      reason(compare.verify(altered),
        'GUARDIAN_EVIDENCE_PACKET_CONTENT_MISMATCH');
    }
  });
});

test('tampering packet digest, authority, status or unknown fields fails before journal read', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const inputs = [
      { ...packet, evidenceSha256: '0'.repeat(64) },
      { ...packet, activationAllowed: true },
      { ...packet, releaseAuthority: 'ISSUED' },
      { ...packet, automaticRestartAllowed: true },
      { ...packet, authority: 'VERIFIED_BY_GITHUB' },
      { ...packet, status: 'ACTIVE' },
      { ...packet, sourceReason: 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP' },
      { ...packet, unexpectedToken: 'PRIVATE_TEST_SECRET' },
      { ...packet, selectedFailure: {
        ...packet.selectedFailure, credential: 'PRIVATE_TEST_SECRET',
      } },
      { ...packet, selectedFailure: null },
    ];
    const compare = verifier(dir);
    for (const input of inputs) {
      const result = compare.verify(input);
      reason(result, 'GUARDIAN_EVIDENCE_PACKET_INVALID');
      assert.equal(result.journalSha256, null);
      assert.equal(result.inspectedEntries, 0);
      assert.equal(JSON.stringify(result).includes('PRIVATE_TEST_SECRET'), false);
    }
  });
});

test('hostile packet getters, symbol keys and throwing Proxy trap do not disclose data', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const compare = verifier(dir);
    let accessed = 0;
    const bad = { ...packet };
    Object.defineProperty(bad, 'journalSha256', {
      enumerable: true,
      get() { accessed++; return packet.journalSha256; },
    });
    const nested = { ...packet, selectedFailure: { ...packet.selectedFailure } };
    Object.defineProperty(nested.selectedFailure, 'state', {
      enumerable: true, get() { accessed++; return 'FAILED'; },
    });
    const traps = [
      bad, nested,
      { ...packet, [Symbol('private')]: 'SECRET' },
      new Proxy({}, { ownKeys() { throw new Error('PRIVATE_TEST_SECRET'); } }),
    ];
    for (const supplied of traps) {
      reason(compare.verify(supplied), 'GUARDIAN_EVIDENCE_PACKET_INVALID');
    }
    assert.equal(accessed, 0);
  });
});

test('reordered JSON packet members are canonicalized only after exact field validation', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const reordered = Object.fromEntries(Object.entries(packet).reverse());
    reason(verifier(dir).verify(reordered),
      'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
  });
});

test('appending to journal invalidates the prior packet even if selected fault still exists', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    writer(dir).append(terminal('STOPPED'));
    const result = verifier(dir).verify(packet);
    reason(result, 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_STALE');
    assert.equal(result.inspectedEntries, 0);
    assert.equal(result.journalSha256, null);
  });
});

test('truncated, duplicated or invalid JSONL is rejected even if attacker re-hashes packet to new bytes', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const original = fs.readFileSync(pathTo(dir), 'utf8');
    const tampered = [
      original.slice(0, -1),
      '{}\n',
      original.replace('"state":"FAILED"',
        '"state":"FAILED","state":"STOPPED"'),
      original + original,
      original.replace('"releaseAuthority":"NOT_ISSUED"',
        '"releaseAuthority":"ISSUED"'),
      '{"privateKey":"PRIVATE_TEST_SECRET"}\n',
    ];
    for (const contents of tampered) {
      fs.writeFileSync(pathTo(dir), contents);
      const input = tamper(packet, (p) => {
        p.journalSha256 = crypto.createHash('sha256')
          .update(Buffer.from(contents)).digest('hex');
      });
      const result = verifier(dir).verify(input);
      reason(result, 'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
      assert.equal(JSON.stringify(result).includes('PRIVATE_TEST_SECRET'), false);
    }
  });
});

test('symlink, unauthorized file mode and missing journal fail closed', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const current = verifier(dir);
    fs.chmodSync(pathTo(dir), 0o644);
    reason(current.verify(packet), 'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
    fs.chmodSync(pathTo(dir), 0o600);
    fs.unlinkSync(pathTo(dir));
    fs.symlinkSync('/dev/null', pathTo(dir));
    reason(current.verify(packet), 'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
    fs.unlinkSync(pathTo(dir));
    reason(current.verify(packet), 'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
  });
});

test('directory privilege drift after construction invalidates verifier immediately', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const current = verifier(dir);
    fs.chmodSync(dir, 0o777);
    try {
      reason(current.verify(packet),
        'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
    } finally { fs.chmodSync(dir, 0o700); }
    reason(current.verify(packet), 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
  });
});

test('journal read quota and verifier construction scope are bounded and fail closed', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    for (const options of [
      { fileName: '../outside.jsonl' },
      { fileName: 'custom.json' },
      { directory: 'relative' },
      { maxBytes: 0 },
      { maxBytes: 100_000_000 },
      { unauthorizedWriter: true },
    ]) {
      assert.throws(() => createGuardianLocalEvidenceVerifier({
        directory: dir, fileName: JOURNAL, ...options,
      }));
    }
    const file = pathTo(dir);
    while (fs.statSync(file).size < 1200) {
      writer(dir).append(terminal('STOPPED'));
    }
    reason(verifier(dir, { maxBytes: 1024 }).verify(packet),
      'GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
  });
});

test('operator facade exposes verification only, preserves strict separation from owner', async () => {
  await temporary(async (dir) => {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(fixture), entrypoint: fixture,
      directory: dir, fileName: JOURNAL,
    });
    assert.deepEqual(Object.keys(session.operator).sort(), [
      'inspect', 'recentEvents', 'incidentEvidence',
      'verifyIncidentEvidence', 'observeLocalContinuity', 'faultTriage',
      'probeRuntime', 'observeRuntimeHealth', 'assessRuntime', 'diagnoseTerminalPersistence', 'assessJournalBudget', 'assessJournalStorage', 'assessTerminalStorage', 'auditCompleteEventLedger', 'captureOfflineIncidentBrief',
    ].sort());
    assert.deepEqual(Object.keys(session.owner).sort(),
      ['start', 'status', 'stop']);
    assert.ok(Object.isFrozen(session.operator));
    for (const key of ['start', 'stop', 'reset', 'clear',
      'acknowledge', 'publishCheck', 'restart']) {
      assert.equal(Object.hasOwn(session.operator, key), false);
    }
    const packet = fill(dir, ['FAILED', 'STOPPED']);
    reason(session.operator.verifyIncidentEvidence(packet),
      'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
    assert.equal(session.owner.status().state, 'CREATED');
    assert.equal(session.operator.inspect().manualInterventionRequired, true);
  });
});

test('local comparison is not OS status attestation or an automatic release', async () => {
  await temporary(async (dir) => {
    const packet = fill(dir, ['FAILED']);
    const claimed = tamper(packet, (p) => { p.processState = 'RUNNING'; });
    const result = verifier(dir).verify(claimed);
    reason(result, 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH');
    assert.equal(result.controllerStateVerified, false);
    assert.equal(result.custodyVerified, false);
    assert.equal(result.manualInterventionRequired, true);
    assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  });
});
