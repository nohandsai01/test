'use strict';
// G37 isolated integration: offline Operator consumers + Generation V2.
// Synthetic local child and owner-only temporary files. No production calls.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalOperatorSession } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianOfflineIncidentBrief } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { generationLedgerName } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const fileName = 'guardian-g37-events.jsonl';

async function fixture(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g37-'));
  try {
    const session = createGuardianLocalOperatorSession({
      cwd:path.dirname(worker), entrypoint:worker, directory, fileName,
      startupTimeoutMs:4000, shutdownTimeoutMs:700,
    });
    return await fn({directory, session});
  } finally {fs.rmSync(directory, {recursive:true, force:true});}
}
function held(x) {
  assert.equal(x.status,'SOURCE_ONLY_HOLD');
  assert.equal(x.activationAllowed,false);
  assert.equal(x.automaticRestartAllowed,false);
  assert.equal(x.releaseAuthority,'NOT_ISSUED');
  assert.equal(x.liveness,'NOT_PROVEN');
  assert.equal(Object.isFrozen(x),true);
}
function noOwnerAuthority(operator) {
  for (const key of ['start','stop','restart','reset','acknowledge',
    'releaseHold','publishCheck','writeD1','clear']) {
    assert.equal(Object.hasOwn(operator,key),false);
  }
}

test('G37 construction is inert; missing journal yields redacted HOLD only', async () => {
  await fixture(({directory,session}) => {
    assert.deepEqual(fs.readdirSync(directory),[]);
    assert.ok(Object.isFrozen(session.operator));
    noOwnerAuthority(session.operator);
    const brief = session.operator.captureOfflineIncidentBrief();
    const audit = session.operator.auditCompleteEventLedger();
    held(brief); held(audit);
    assert.notEqual(brief.classification,'LOCAL_BRIEF_CONSISTENT');
    assert.equal(brief.events.length,0);
    assert.equal(audit.comparison,'NOT_VERIFIED');
    assert.equal(audit.journalSha256,null);
    assert.deepEqual(fs.readdirSync(directory),[]);
    assert.equal(session.owner.status().state,'CREATED');
  });
});

test('G37 authentic V2 lifecycle is readable through BOTH fixed read-only facades', async () => {
  await fixture(async ({directory,session}) => {
    assert.equal((await session.owner.start()).state,'RUNNING');
    assert.equal((await session.owner.stop()).state,'STOPPED');
    const journal = path.join(directory,fileName);
    const ledger = path.join(directory,generationLedgerName(fileName));
    assert.equal(fs.existsSync(journal),true);
    assert.equal(fs.existsSync(ledger),true);
    const before = [fs.readFileSync(journal),fs.readFileSync(ledger)];
    const assessment = session.operator.assessRuntime();
    assert.equal(assessment.unterminatedGenerations,0);
    const brief = session.operator.captureOfflineIncidentBrief();
    const audit = session.operator.auditCompleteEventLedger();
    held(brief);held(audit);
    assert.equal(brief.classification,'LOCAL_BRIEF_CONSISTENT');
    assert.equal(audit.comparison,'MATCH_LOCAL_PAGES_ONLY');
    assert.equal(brief.processState,'STOPPED');
    assert.equal(audit.processState,'STOPPED');
    assert.equal(brief.journalSha256,audit.journalSha256);
    assert.equal(brief.journalEntries,audit.inspectedEntries);
    assert.equal(brief.historicalFailureCount,audit.failureCount);
    assert.equal(brief.events.length,1);
    assert.equal(brief.events[0].state,'STOPPED');
    assert.equal(Object.isFrozen(brief.events),true);
    assert.equal(Object.isFrozen(audit.failureCodes),true);
    for (const key of ['pid','generationId','token','secret','rawJournal',
      'privateKey','path','launchLedgerBytes']) {
      assert.equal(Object.hasOwn(brief,key),false);
      assert.equal(Object.hasOwn(audit,key),false);
    }
    assert.deepEqual(fs.readFileSync(journal),before[0]);
    assert.deepEqual(fs.readFileSync(ledger),before[1]);
    noOwnerAuthority(session.operator);
  });
});

test('G37 local launch ledger corruption cannot produce a healthy evidence summary', async () => {
  await fixture(async ({directory,session}) => {
    await session.owner.start();
    await session.owner.stop();
    const ledger = path.join(directory,generationLedgerName(fileName));
    // Only a synthetic temporary fixture is modified here.
    fs.appendFileSync(ledger,'{"malformed":true}\n');
    const brief = session.operator.captureOfflineIncidentBrief();
    const audit = session.operator.auditCompleteEventLedger();
    held(brief); held(audit);
    assert.notEqual(brief.classification,'LOCAL_BRIEF_CONSISTENT');
    assert.equal(brief.events.length,0);
    assert.equal(audit.comparison,'NOT_VERIFIED');
    assert.equal(audit.inspectedEntries,0);
  });
});

test('G37 offline capture rejects changed generation counts between observations', async () => {
  await fixture(async ({session}) => {
    await session.owner.start(); await session.owner.stop();
    const real = session.operator.assessRuntime();
    const legacyCompatible = Object.freeze({
      ...real, priority:'P2',classification:'PROCESS_STATE_UNPROVEN',
      nextAction:'OWNER_RECONCILE_LIFECYCLE',
      manualInterventionRequired:true, unterminatedGenerations:0,
    });
    const changed = Object.freeze({
      ...legacyCompatible, unterminatedGenerations:1,
    });
    let reads = 0;
    const probe = createGuardianOfflineIncidentBrief({operator:{
      assessRuntime:() => (++reads===1 ? legacyCompatible : changed),
      recentEvents:(options) => session.operator.recentEvents(options),
    }});
    const outcome=probe.capture();
    held(outcome);
    assert.equal(outcome.classification,'LOCAL_BRIEF_EVIDENCE_CHANGED');
    assert.equal(outcome.priority,'P0');
    assert.equal(outcome.events.length,0);
    assert.equal(outcome.journalSha256,null);
    assert.equal(reads,2);
  });
});

test('G37 rejects forged V2 generation metadata instead of silently downgrading', async () => {
  await fixture(async ({session}) => {
    await session.owner.start(); await session.owner.stop();
    const real = session.operator.assessRuntime();
    const fake = Object.freeze({...real, unterminatedGenerations:'0'});
    const observer = createGuardianOfflineIncidentBrief({operator:{
      assessRuntime:() => fake,
      recentEvents:() => {throw Error('MUST_NOT_QUERY_INVALID_BASELINE');},
    }});
    const report=observer.capture();
    held(report);
    assert.equal(report.classification,'LOCAL_BRIEF_SOURCE_UNVERIFIED');
    assert.equal(report.events.length,0);
  });
});
