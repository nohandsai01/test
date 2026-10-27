'use strict';
// G27C pure offline structural history checks across checksum-valid briefs.
// No source-authenticity claim, online API, IPC or program generation work.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianOfflineIncidentBrief } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { createGuardianLocalReceiptJournal } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const {
  verifyBrief, makeBundle, compareBriefHistory, verifyBundleHistory,
} = require('../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const stop = () => ({
  state: 'STOPPED', errorCode: null, hostStopped: true,
  activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
  automaticRestartAllowed: false,
});
const fail = () => ({
  state: 'FAILED', errorCode: 'GUARDIAN_CHILD_EXIT_UNVERIFIED',
  hostStopped: false, activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
});

async function temp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g27c-'));
  try {
    const fileName = 'guardian-offline-history.jsonl';
    const journal = createGuardianLocalReceiptJournal({ directory, fileName });
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(worker), entrypoint: worker, directory, fileName,
      startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
    });
    const capture = (limit = 10) =>
      createGuardianOfflineIncidentBrief({ operator: session.operator, limit })
        .capture();
    return await fn({ directory, journal, capture });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function assertHold(result) {
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.equal(result.automaticRestartAllowed, false);
  assert.equal(result.manualInterventionRequired, true);
  assert.equal(result.custodyVerified, false);
  assert.ok(Object.isFrozen(result));
}
function compatible(r, reason, appended) {
  assertHold(r);
  assert.equal(r.comparison, 'LOCAL_STRUCTURAL_OBSERVATION_ONLY');
  assert.equal(r.reason, reason);
  assert.equal(r.appendedEntries, appended);
}
function denied(r, reason) {
  assertHold(r);
  assert.equal(r.comparison, 'NOT_VERIFIED');
  assert.equal(r.reason, reason);
  assert.equal(r.olderJournalSha256, null);
  assert.equal(r.newerJournalSha256, null);
  assert.equal(r.appendedEntries, 0);
}
test('inert exports do not write or produce release authority', async () => {
  await temp(async ({ directory, capture }) => {
    assert.equal(fs.readdirSync(directory).length, 0);
    assert.deepEqual(Object.keys(require(
      '../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs')).sort(), [
      'verifyBrief','makeBundle','verifyBundle','compareBriefHistory',
      'verifyBundleHistory'].sort());
    const r = compareBriefHistory(null, undefined);
    denied(r, 'GUARDIAN_BRIEF_CONTINUITY_SOURCE_UNVERIFIED');
    const b = verifyBundleHistory(null);
    assertHold(b);
    assert.equal(b.comparison, 'NOT_VERIFIED');
    assert.equal(fs.readdirSync(directory).length, 0);
  });
});
test('identical full journal snapshots are locally equal but never trusted liveness', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop()); journal.append(fail()); journal.append(stop());
    const old = capture(), duplicate = capture();
    assert.equal(verifyBrief(old).comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
    assert.equal(old.briefSha256, duplicate.briefSha256);
    const result = compareBriefHistory(old, JSON.stringify(duplicate));
    compatible(result, 'GUARDIAN_BRIEF_SAME_LOCAL_SNAPSHOT', 0);
    assert.equal(result.olderEntryCount, 3);
    assert.equal(result.newerEntryCount, 3);
    assert.equal(result.olderJournalSha256, result.newerJournalSha256);
  });
});
test('append one STOPPED event preserves prior complete newest-first history', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop()); journal.append(fail());
    const older = capture();
    journal.append(stop());
    const newer = capture();
    assert.notEqual(older.journalSha256, newer.journalSha256);
    const r = compareBriefHistory(JSON.stringify(older), newer);
    compatible(r, 'GUARDIAN_BRIEF_STRUCTURAL_APPEND_COMPATIBLE', 1);
    assert.equal(r.olderEntryCount, 2);
    assert.equal(r.newerEntryCount, 3);
  });
});
test('append FAILED events increases historical fault count by the actual new faults', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());
    const a = capture();
    journal.append(fail()); journal.append(stop()); journal.append(fail());
    const b = capture();
    const r = compareBriefHistory(a, b);
    compatible(r, 'GUARDIAN_BRIEF_STRUCTURAL_APPEND_COMPATIBLE', 3);
    assert.equal(b.historicalFailureCount - a.historicalFailureCount, 2);
  });
});
test('consistent history across 3 snapshots survives a checked bundle handoff', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());
    const a = capture();
    journal.append(fail());
    const b = capture();
    journal.append(stop());
    const c = capture();
    const bundle = makeBundle([a,b,c]);
    for (const source of [bundle, JSON.stringify(bundle)]) {
      const r = verifyBundleHistory(source);
      assertHold(r);
      assert.equal(r.comparison, 'LOCAL_STRUCTURAL_OBSERVATION_ONLY');
      assert.equal(r.reason,
        'GUARDIAN_BRIEF_BUNDLE_HISTORY_STRUCTURALLY_COMPATIBLE');
      assert.equal(r.bundleSha256, bundle.bundleSha256);
      assert.deepEqual(r.comparisons.map((x) => x.appendedEntries), [1,1]);
      assert.equal(Object.isFrozen(r.comparisons), true);
      assert.equal(r.comparisons.every(Object.isFrozen), true);
      assert.equal(Object.hasOwn(r,'briefs'), false);
      assert.equal(Object.hasOwn(r,'events'), false);
    }
  });
});
test('full history beyond 10 entries refuses falsely complete lineage', async () => {
  await temp(async ({ journal, capture }) => {
    for (let i=0; i<10; i++) journal.append(stop());
    const old = capture();
    journal.append(fail());
    const newer = capture();
    const r = compareBriefHistory(old, newer);
    denied(r, 'GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY');
    const bundled = verifyBundleHistory(makeBundle([old,newer]));
    assert.equal(bundled.comparison, 'NOT_VERIFIED');
    assert.equal(bundled.reason,
      'GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY');
    assert.equal(bundled.comparisons.length,0);
  });
});
test('partially paginated prior reports cannot assert append compatibility', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop()); journal.append(stop()); journal.append(fail());
    const partial = capture(1), complete = capture(3);
    assert.equal(partial.journalSha256, complete.journalSha256);
    denied(compareBriefHistory(partial,complete),
      'GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY');
  });
});
test('wrong chronology, wrong counts or mixing different journals fails without events', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());journal.append(fail());
    const older = capture();
    journal.append(stop());
    const newer = capture();
    for (const inputs of [
      [newer, older],
      [older, {...newer, briefSha256:'0'.repeat(64)}],
      [older, JSON.stringify(newer).replace('"state":"STOPPED"',
        '"state":"FAILED"')],
      [older, {...older, journalSha256:newer.journalSha256}],
    ]) {
      const r = compareBriefHistory(...inputs);
      assertHold(r);
      assert.equal(r.comparison, 'NOT_VERIFIED');
      assert.equal(r.appendedEntries,0);
    }
  });
});
test('reordered event array with recomputed checksum still violates structural suffix', async () => {
  const crypto = require('node:crypto');
  await temp(async ({ journal, capture }) => {
    journal.append(stop());journal.append(fail());
    const a = capture();
    journal.append(stop());
    const b = structuredClone(capture());
    b.events.reverse();
    const raw = {};
    for (const key of Object.keys(b)) {
      if (key !== 'briefSha256') raw[key] = b[key];
    }
    b.briefSha256 = crypto.createHash('sha256')
      .update(JSON.stringify(raw),'utf8').digest('hex');
    assert.equal(verifyBrief(b).comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
    denied(compareBriefHistory(a, b), 'GUARDIAN_BRIEF_CONTINUITY_CONFLICT');
  });
});
test('malicious metadata and duplicate JSON members cannot fake an append', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop()); journal.append(fail());
    const a = capture();
    journal.append(stop());
    const b = capture();
    const input = JSON.stringify(b);
    for (const altered of [
      input.replace('"priority":"P1"','"priority":"P1","priority":"P0"'),
      input.replace('"state":"STOPPED"','"state":"STOPPED","state":"FAILED"'),
      input+' TRAILING',
      '{bad json}',
    ]) {
      denied(compareBriefHistory(a,altered),
        'GUARDIAN_BRIEF_CONTINUITY_SOURCE_UNVERIFIED');
    }
  });
});
test('proxy/accessor/symbol/array-iterator traps fail without secret echoes', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());
    const a = capture();
    journal.append(fail());
    const b = capture();
    const accessor = structuredClone(b);
    Object.defineProperty(accessor,'events',{
      get() {throw new Error('VERY_PRIVATE_KEY');}
    });
    const proxy = new Proxy(b, {ownKeys(){throw Error('TOP_SECRET');}});
    const symbol = structuredClone(b);
    symbol[Symbol('secret')] = 'TOP_SECRET';
    for(const item of [accessor,proxy,symbol]) {
      const r = compareBriefHistory(a,item);
      assertHold(r);
      assert.equal(r.comparison,'NOT_VERIFIED');
      assert.ok(!JSON.stringify(r).includes('PRIVATE'));
      assert.ok(!JSON.stringify(r).includes('SECRET'));
    }
  });
});
test('bundle replay/order reversal, duplicates and changed nested JSON are NOT_VERIFIED', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());
    const a = capture();
    journal.append(fail());
    const b = capture();
    const bundle = makeBundle([a,b]);
    for (const bad of [
      makeBundle([b,a]),
      JSON.stringify(bundle).replace('"count":2','"count":2,"count":2'),
      JSON.stringify(bundle).replace('"priority":"P2"',
        '"priority":"P2","priority":"P0"'),
      structuredClone({...bundle, bundleSha256:'a'.repeat(64)}),
    ]) {
      const result = verifyBundleHistory(bad);
      assertHold(result);
      assert.equal(result.comparison,'NOT_VERIFIED');
      assert.equal(result.bundleSha256,null);
      assert.equal(result.comparisons.length,0);
    }
  });
});
test('invalid P0 brief cannot ever establish program history, despite its valid checksum', async () => {
  await temp(async ({ journal, capture }) => {
    const empty = capture();
    journal.append(stop());
    const good = capture();
    assert.equal(verifyBrief(empty).comparison,'MATCH_LOCAL_CHECKSUM_ONLY');
    denied(compareBriefHistory(empty,good),
      'GUARDIAN_BRIEF_CONTINUITY_SOURCE_UNVERIFIED');
    const history = verifyBundleHistory(makeBundle([empty,good]));
    assert.equal(history.comparison,'NOT_VERIFIED');
    assert.equal(history.reason,
      'GUARDIAN_BRIEF_CONTINUITY_SOURCE_UNVERIFIED');
  });
});
test('no report is a custody attestation or restart permission even after matching', async () => {
  await temp(async ({ journal, capture }) => {
    journal.append(stop());
    const a = capture();
    journal.append(stop());
    const b = capture();
    const r = compareBriefHistory(a,b);
    compatible(r,'GUARDIAN_BRIEF_STRUCTURAL_APPEND_COMPATIBLE',1);
    for (const field of ['pid','generation','trusted','signature',
      'checkWriter','restart','clearHold','rawJournal','token']) {
      assert.equal(Object.hasOwn(r,field),false);
    }
    assert.equal(r.custodyVerified,false);
  });
});
