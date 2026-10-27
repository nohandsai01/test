'use strict';
// Offline brief checksum verification + bounded operator handoff only.
// Never a signature, custody proof, process liveness or release authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyBrief, makeBundle, verifyBundle } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');
const { createGuardianOfflineIncidentBrief } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
async function fixture(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-brief-verifier-'));
  try {
    const fileName = 'guardian-offline-verifier.jsonl';
    const journal = createGuardianLocalReceiptJournal({ directory, fileName });
    const stop = { state:'STOPPED', errorCode:null, hostStopped:true,
      activationAllowed:false, releaseAuthority:'NOT_ISSUED',
      automaticRestartAllowed:false };
    const failed = { state:'FAILED', errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',
      hostStopped:false, activationAllowed:false, releaseAuthority:'NOT_ISSUED',
      automaticRestartAllowed:false };
    journal.append(stop);
    journal.append(failed);
    journal.append(stop);
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(worker), entrypoint: worker,
      directory, fileName, startupTimeoutMs:4000, shutdownTimeoutMs:900,
    });
    const capture = (limit) =>
      createGuardianOfflineIncidentBrief({ operator: session.operator, limit }).capture();
    const first = capture(3), second = capture(2);
    assert.equal(first.classification, 'LOCAL_BRIEF_CONSISTENT');
    assert.equal(second.classification, 'LOCAL_BRIEF_CONSISTENT');
    assert.notEqual(first.briefSha256, second.briefSha256);
    return await fn({ first, second, directory, capture });
  } finally { fs.rmSync(directory, { recursive:true, force:true }); }
}
function assertHold(x) {
  assert.equal(x.status, 'SOURCE_ONLY_HOLD');
  assert.equal(x.liveness, 'NOT_PROVEN');
  assert.equal(x.activationAllowed, false);
  assert.equal(x.releaseAuthority, 'NOT_ISSUED');
  assert.equal(x.automaticRestartAllowed, false);
  assert.equal(x.manualInterventionRequired, true);
  assert.equal(Object.isFrozen(x), true);
}
function source(x) { return JSON.stringify(x); }
function jsonEdit(x, edit) { return JSON.parse(edit(JSON.stringify(x))); }

test('verifier import is inert; real offline brief matches checksum and exposes no events', async () => {
  await fixture(async ({ first }) => {
    for (const input of [first, source(first)]) {
      const answer = verifyBrief(input);
      assertHold(answer);
      assert.equal(answer.comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
      assert.equal(answer.reason, 'GUARDIAN_BRIEF_LOCAL_CHECKSUM_MATCH');
      assert.equal(answer.priority, 'P1');
      assert.equal(answer.eventCount, 3);
      assert.equal(answer.briefSha256, first.briefSha256);
      assert.equal(answer.journalSha256, first.journalSha256);
      for (const sensitive of ['events', 'privateKey', 'rawJournal', 'pid',
        'token', 'CheckWriter', 'clearHold']) {
        assert.equal(Object.hasOwn(answer, sensitive), false);
      }
    }
  });
});

test('valid bundle handoff is immutable, roundtrips JSON and binds exact report digests', async () => {
  await fixture(async ({ first, second }) => {
    const before = { a: JSON.stringify(first), b: JSON.stringify(second) };
    const bundle = makeBundle([first, second]);
    assertHold(bundle);
    assert.equal(bundle.count, 2);
    assert.equal(bundle.briefs.length, 2);
    assert.equal(Object.isFrozen(bundle.briefs), true);
    assert.match(bundle.bundleSha256, /^[0-9a-f]{64}$/);
    const string = JSON.stringify(bundle);
    for (const value of [bundle, string]) {
      const checked = verifyBundle(value);
      assertHold(checked);
      assert.equal(checked.comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
      assert.equal(checked.reason, 'GUARDIAN_BRIEF_BUNDLE_CHECKSUM_MATCH');
      assert.equal(checked.bundleSha256, bundle.bundleSha256);
      assert.deepEqual(checked.briefDigests,
        [first.briefSha256, second.briefSha256]);
      assert.equal(checked.count, 2);
      assert.equal(Object.hasOwn(checked, 'briefs'), false);
      assert.equal(Object.isFrozen(checked.briefDigests), true);
    }
    assert.equal(JSON.stringify(first), before.a);
    assert.equal(JSON.stringify(second), before.b);
  });
});

test('changing a single event, priority, SHA or authorizing metadata invalidates offline checksum', async () => {
  await fixture(async ({ first }) => {
    for (const mutation of [
      (x) => { x.events[0].errorCode = 'GUARDIAN_CHILD_EXIT_UNVERIFIED'; },
      (x) => { x.events[0].eventId = '00000000-0000-4000-8000-000000000001'; },
      (x) => { x.healthFreshness = 'RECENT'; },
      (x) => { x.priority = 'P3'; },
      (x) => { x.journalSha256 = '0'.repeat(64); },
      (x) => { x.releaseAuthority = 'ISSUED'; },
      (x) => { x.activationAllowed = true; },
      (x) => { x.events[0].token = 'DO_NOT_LEAK_SECRET'; },
      (x) => { x.unexpected = 'DO_NOT_LEAK_SECRET'; },
    ]) {
      const changed = structuredClone(first);
      mutation(changed);
      const r = verifyBrief(changed);
      assertHold(r);
      assert.equal(r.comparison, 'NOT_VERIFIED');
      assert.equal(r.priority, 'P0');
      assert.equal(r.briefSha256, null);
      assert.equal(r.eventCount, 0);
      assert.equal(JSON.stringify(r).includes('DO_NOT_LEAK_SECRET'), false);
    }
  });
});

test('raw JSON duplicate object keys at root, nested event or bundle level are rejected', async () => {
  await fixture(async ({ first, second }) => {
    const json = JSON.stringify(first);
    const wrongRoot = json.replace('"priority":"P1"', '"priority":"P1","priority":"P0"');
    const wrongNested = json.replace('"state":"STOPPED"', '"state":"STOPPED","state":"FAILED"');
    for (const data of [wrongRoot, wrongNested]) {
      const output = verifyBrief(data);
      assertHold(output);
      assert.equal(output.comparison, 'NOT_VERIFIED');
    }
    const bundle = makeBundle([first, second]);
    const raw = JSON.stringify(bundle);
    const repeated = raw.replace('"count":2', '"count":2,"count":2');
    const nested = raw.replace('"priority":"P1"', '"priority":"P1","priority":"P0"');
    for (const input of [repeated,nested]) {
      const report = verifyBundle(input);
      assertHold(report);
      assert.equal(report.comparison, 'NOT_VERIFIED');
      assert.equal(report.count, 0);
    }
  });
});

test('dynamic accessors, Proxy traps, prototype pollution and sparse event arrays fail closed', async () => {
  await fixture(async ({ first, second }) => {
    const dynamic = Object.defineProperty(structuredClone(first), 'events', {
      get() { throw new Error('PRIVATE_TOKEN_LEAK'); },
    });
    const proxied = new Proxy(first, {
      ownKeys() { throw new Error('PRIVATE_KEY_LEAK'); },
    });
    const prototype = Object.assign(Object.create({ token: true }), structuredClone(first));
    const sparse = structuredClone(first);
    sparse.events = new Array(3);
    for (const item of [dynamic, proxied, prototype, sparse]) {
      const answer = verifyBrief(item);
      assertHold(answer);
      assert.equal(answer.comparison, 'NOT_VERIFIED');
      assert.equal(JSON.stringify(answer).includes('PRIVATE'), false);
    }
    const bundle = makeBundle([first, second]);
    const bad = structuredClone(bundle);
    Object.defineProperty(bad, 'briefs', {
      get() { throw new Error('SECRET_BUNDLE'); },
    });
    const outcome = verifyBundle(bad);
    assertHold(outcome);
    assert.equal(outcome.comparison, 'NOT_VERIFIED');
  });
});

test('duplicate brief members, bad limits, sparse bundle arrays and extra keys never hand off', async () => {
  await fixture(async ({ first, second }) => {
    for (const input of [
      [], [first,first], new Array(1), new Array(9).fill(first),
      [first,{...second,token:'LEAK'}],
    ]) assert.throws(() => makeBundle(input));
    const valid = makeBundle([first, second]);
    for (const mutation of [
      (x) => { x.bundleSha256 = '0'.repeat(64); },
      (x) => { x.count = 1; },
      (x) => { x.releaseAuthority = 'ISSUED'; },
      (x) => { x.extra = 'PRIVATE'; },
      (x) => { x.briefs[0].events[0].state = 'FAILED'; },
      (x) => { x.briefs[1] = x.briefs[0]; },
    ]) {
      const invalid = structuredClone(valid);
      mutation(invalid);
      const result = verifyBundle(invalid);
      assertHold(result);
      assert.equal(result.comparison, 'NOT_VERIFIED');
      assert.equal(result.bundleSha256, null);
      assert.equal(result.count, 0);
    }
  });
});

test('each invalid local brief is nonauthorizing and cannot be converted into a consistent transfer', async () => {
  await fixture(async ({ first }) => {
    const corrupt = structuredClone(first);
    corrupt.events[0].timestamp = 'INVALID DATE';
    const r = verifyBrief(corrupt);
    assertHold(r);
    assert.equal(r.comparison, 'NOT_VERIFIED');
    assert.throws(() => makeBundle([corrupt]));
    const wrong = JSON.stringify(first).replace('"briefSha256":"',
      '"briefSha256":"x');
    assert.equal(verifyBrief(wrong).comparison, 'NOT_VERIFIED');
  });
});

test('an unverified P0 source brief is still checksum-checked but never becomes acceptable evidence', async () => {
  const stub = { assessRuntime: () => Object.freeze({
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD', priority: 'P0',
  }), recentEvents() { throw Error('must not be called'); } };
  const report = createGuardianOfflineIncidentBrief({operator:stub}).capture();
  assert.equal(report.classification, 'LOCAL_BRIEF_SOURCE_UNVERIFIED');
  const outcome = verifyBrief(report);
  assertHold(outcome);
  assert.equal(outcome.comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
  assert.equal(outcome.priority, 'P0');
  assert.equal(outcome.eventCount, 0);
  const bundle = makeBundle([report]);
  const valid = verifyBundle(JSON.stringify(bundle));
  assertHold(valid);
  assert.equal(valid.comparison, 'MATCH_LOCAL_CHECKSUM_ONLY');
  assert.equal(valid.count, 1);
  assert.equal(valid.briefDigests[0], report.briefSha256);
});

test('oversize JSON and malformed input fail without a raw echo or network effects', async () => {
  await fixture(async ({ first }) => {
    for (const raw of [
      '', '{', '[1,2]', ' '.repeat(96_100),
      JSON.stringify(first) + ' trailing injection',
      JSON.stringify({ ...first, events: 'DO_NOT_LOG_PRIVATE_KEY' }),
    ]) {
      const answer = verifyBrief(raw);
      assertHold(answer);
      assert.equal(answer.comparison, 'NOT_VERIFIED');
      assert.equal(JSON.stringify(answer).includes('DO_NOT_LOG'), false);
    }
    for (const raw of [
      '', '[]', '{}', ' '.repeat(96_100),
      '{"bundleSha256":"secret"}',
    ]) {
      const answer = verifyBundle(raw);
      assertHold(answer);
      assert.equal(answer.comparison, 'NOT_VERIFIED');
    }
  });
});
